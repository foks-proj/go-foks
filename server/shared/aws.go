// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type AWSRoute53DNSSetter struct {
	zones   []DNSZoner
	zonemap map[proto.Hostname]proto.ZoneID
	creds   AWSCredentialer
	cfg     *aws.Config
	svc     *route53.Client
}

func NewAWSRoute53DNSSetter(zones []DNSZoner, creds AWSCredentialer) *AWSRoute53DNSSetter {
	return &AWSRoute53DNSSetter{zones: zones, creds: creds}
}

const DefAWSRegion = "us-east-1"

func (r *AWSRoute53DNSSetter) awsConfig(m MetaContext) (*aws.Config, error) {
	if r.cfg != nil {
		return r.cfg, nil
	}

	var rgn string
	if r.creds != nil {
		rgn = r.creds.Region()
	}

	if rgn == "" {
		rgn = DefAWSRegion
		m.Warnw("AWSRoute53.awsConfig", "no_creds", true, "region", rgn)
	}

	if r.creds == nil || r.creds.AccessKey() == "" {
		m.Infow("AWSRoute53.awsConfig", "region", rgn)
		cfg, err := config.LoadDefaultConfig(m.Ctx(), config.WithRegion(rgn))
		if err != nil {
			return nil, err
		}
		r.cfg = &cfg
		return r.cfg, nil
	}

	if r.creds.SecretKey() == "" {
		return nil, core.ConfigError("missing AWS secret key")
	}

	customCreds := aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
		r.creds.AccessKey(),
		r.creds.SecretKey(),
		"",
	))
	cfg, err := config.LoadDefaultConfig(m.Ctx(),
		config.WithCredentialsProvider(customCreds),
		config.WithRegion(r.creds.Region()))
	if err != nil {
		return nil, err
	}
	r.cfg = &cfg
	return r.cfg, nil
}

func (r *AWSRoute53DNSSetter) route53Cli(m MetaContext) (*route53.Client, error) {
	if r.svc != nil {
		return r.svc, nil
	}
	cfg, err := r.awsConfig(m)
	if err != nil {
		return nil, err
	}
	r.svc = route53.NewFromConfig(*cfg)
	return r.svc, nil
}

func (r *AWSRoute53DNSSetter) Init(m MetaContext) error {

	r.zonemap = make(map[proto.Hostname]proto.ZoneID)
	for _, z := range r.zones {
		r.zonemap[z.Domain().Normalize()] = z.ZoneID()
	}
	return nil
}

func (r *AWSRoute53DNSSetter) findZone(
	h proto.Hostname,
) *proto.ZoneID {
	domains := h.AllSuperdomains()
	for _, d := range domains {
		if z, ok := r.zonemap[d.Normalize()]; ok {
			return &z
		}
	}
	return nil
}

func (r *AWSRoute53DNSSetter) sendChange(
	m MetaContext,
	h proto.Hostname,
	change types.Change,
) (
	*route53.ChangeResourceRecordSetsOutput,
	error,
) {
	svc, err := r.route53Cli(m)
	if err != nil {
		return nil, err
	}

	zone := r.findZone(h)
	if zone == nil {
		return nil, core.NotFoundError(
			fmt.Sprintf("domain for hostname %s", h),
		)
	}

	// Create the change batch
	changeBatch := &types.ChangeBatch{
		Changes: []types.Change{change},
	}

	// Create the request to change the record set
	input := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zone.String()),
		ChangeBatch:  changeBatch,
	}

	// Call the ChangeResourceRecordSets API to apply the change
	return svc.ChangeResourceRecordSets(m.Ctx(), input)
}

func (r *AWSRoute53DNSSetter) SetCNAME(m MetaContext, from proto.Hostname, to proto.Hostname) error {
	recordChange := types.Change{
		Action: types.ChangeActionUpsert, // Use 'Upsert' to create or update the record
		ResourceRecordSet: &types.ResourceRecordSet{
			Name: aws.String(from.String()),
			Type: types.RRTypeCname,
			TTL:  aws.Int64(60), // TTL in seconds
			ResourceRecords: []types.ResourceRecord{
				{
					Value: aws.String(to.String()), // The value of the CNAME
				},
			},
		},
	}
	// Call the ChangeResourceRecordSets API to apply the change
	resp, err := r.sendChange(m, from, recordChange)
	if err != nil {
		return err
	}
	m.Infow("AWSRoute53.SetCNAME",
		"id", *resp.ChangeInfo.Id, "from", from,
		"to", to)
	return nil
}

func (r *AWSRoute53DNSSetter) ClearCNAME(m MetaContext, nm proto.Hostname) error {
	del := types.Change{
		Action: types.ChangeActionDelete,
		ResourceRecordSet: &types.ResourceRecordSet{
			Name: aws.String(nm.String()),
			Type: types.RRTypeCname,
		},
	}
	resp, err := r.sendChange(m, nm, del)
	if err != nil {
		return err
	}
	m.Infow("AWSRoute53.ClearCNAME",
		"id", *resp.ChangeInfo.Id, "name", nm)
	return nil
}
