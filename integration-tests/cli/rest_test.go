package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/foks-proj/go-foks/client/libkv"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	"github.com/stretchr/testify/require"
)

func TestKVRest(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)
	parentPath := "/" + fsRandomString(t, 8)
	b := bob.agent
	b.runCmd(t, nil, "kv", "mkdir", "-p", parentPath)

	cook := func(n int, team string) ([]string, map[string]string) {
		var paths []string
		data := make(map[string]string)
		for range n {
			dat := fsRandomString(t, 0)
			name := fsRandomString(t, 24)
			path := parentPath + "/" + name
			paths = append(paths, path)
			args := []string{"kv", "put"}
			if len(team) > 0 {
				args = append(args, "-t", team)
			}
			args = append(args, path, dat)
			b.runCmd(t, nil, args...)
			data[path] = dat
		}
		return paths, data
	}
	paths, data := cook(21, "")

	slices.Sort(paths)

	tok := fsRandomString(t, 16)

	var info lcl.KVRestListenInfo
	b.runCmdToJSON(t, &info, "kv", "rest", "start", "--port", "0", "--auth-token", tok)

	mkPath := func(path string, party string) string {
		var leading string
		if len(path) > 0 && path[0] != '/' {
			leading = "/"
		}
		return fmt.Sprintf("http://localhost:%d/v0/%s%s%s", info.Port, party, leading, path)
	}

	addAuth := func(req *http.Request) {
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", tok))
	}
	listWithPath := func(n int, nxt *libkv.ListNextJSON, parentPath string, party string) *libkv.ListPageJSON {
		client := &http.Client{}

		qry := fmt.Sprintf("%s/?page_entries=%d", mkPath(parentPath, party), n)
		if nxt != nil {
			require.NotNil(t, nxt.Pagination.Hmac)
			qry += fmt.Sprintf("&page_hmac=%s&page_dir_id=%s", *nxt.Pagination.Hmac, nxt.DirID)
		}
		req, err := http.NewRequest("GET", qry, nil)
		require.NoError(t, err)
		addAuth(req)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var list libkv.ListPageJSON
		err = json.NewDecoder(resp.Body).Decode(&list)
		require.NoError(t, err)
		return &list
	}

	list := func(n int, nxt *libkv.ListNextJSON, party string) *libkv.ListPageJSON {
		return listWithPath(n, nxt, parentPath, party)
	}

	listUser := func(n int, nxt *libkv.ListNextJSON) *libkv.ListPageJSON {
		return list(n, nxt, "-")
	}

	fetch := func(path string, party string) []byte {
		client := &http.Client{}
		qry := mkPath(path, party)
		req, err := http.NewRequest("GET", qry, nil)
		require.NoError(t, err)
		addAuth(req)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var buf bytes.Buffer
		_, err = buf.ReadFrom(resp.Body)
		require.NoError(t, err)
		return buf.Bytes()
	}
	fetchUser := func(path string) []byte {
		return fetch(path, "-")
	}

	fetchGetErr := func(path string, party string, code int, msg string) {
		client := &http.Client{}
		qry := mkPath(path, party)
		req, err := http.NewRequest("GET", qry, nil)
		require.NoError(t, err)
		addAuth(req)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, code, resp.StatusCode)
		var buf bytes.Buffer
		_, err = buf.ReadFrom(resp.Body)
		require.NoError(t, err)
		require.Equal(t, msg, buf.String())
	}

	put := func(path string, dat []byte, party string) {
		client := &http.Client{}
		qry := mkPath(path, party)
		var buf bytes.Buffer
		_, err := buf.Write(dat)
		require.NoError(t, err)
		req, err := http.NewRequest("PUT", qry, &buf)
		require.NoError(t, err)
		addAuth(req)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
	}
	putUser := func(path string, dat []byte) {
		put(path, dat, "-")
	}

	n := 12
	page := listUser(n, nil)
	require.NotNil(t, page.Next)
	require.NotNil(t, page.Next.Pagination)
	require.Equal(t, parentPath+"/", page.Parent)
	require.Len(t, page.Entries, n)

	page2 := listUser(n, page.Next)
	require.Nil(t, page2.Next)
	require.Equal(t, parentPath+"/", page2.Parent)
	require.Len(t, page2.Entries, 9)

	ent := parentPath + "/" + page2.Entries[3].Name
	dat := fetchUser(ent)
	expected := data[ent]
	require.Equal(t, expected, string(dat))
	require.Equal(t, "file", page2.Entries[3].Type)

	bad := ent + "XXXXX"
	fetchGetErr(bad, "-", http.StatusNotFound, "not found\n")

	// Asking to list a non-directory gets an error 400
	fetchGetErr(ent+"/", "-", http.StatusNotFound, "resource of specified type not found\n")

	dat, err := core.RandomBytes(1024 * 1024)
	require.NoError(t, err)
	name := fsRandomString(t, 24)
	path := parentPath + "/" + name
	putUser(path, dat)

	dat2 := b.runCmdToBytes(t, "kv", "get", "--force-output", path, "-")
	require.Equal(t, dat, dat2)

	// now make sure that when we ls and hit a dir, we get the right file type
	dat, err = core.RandomBytes(1024 * 1024)
	require.NoError(t, err)
	totalPath := fsRandomString(t, 24)

	totalPathParent := parentPath + "/" + totalPath[0:8]
	totalPath = totalPathParent + "/" + totalPath[8:16] + "/" + totalPath[16:]

	putUser(totalPath, dat)
	page = listWithPath(10, nil, totalPathParent, "-")
	require.Nil(t, page.Next)
	require.Len(t, page.Entries, 1)
	require.Equal(t, page.Entries[0].Type, "dir")

	// Now do the same thing, but on behalf of a team...
	tm := "t-" + strings.ToLower(fsRandomString(t, 10))
	merklePoke(t)
	var res lcl.TeamCreateRes
	b.runCmdToJSON(t, &res, "team", "create", tm)
	merklePoke(t)

	b.runCmd(t, nil, "kv", "mkdir", "-p", "-t", tm, parentPath)
	_, data = cook(5, tm)

	page = list(12, nil, "t:"+tm)
	require.Nil(t, page.Next)
	ent = parentPath + "/" + page.Entries[3].Name
	dat = fetch(ent, "t:"+tm)
	expected = data[ent]
	require.Equal(t, expected, string(dat))

	dat, err = core.RandomBytes(1024 * 1024)
	require.NoError(t, err)
	name = fsRandomString(t, 24)
	path = parentPath + "/" + name
	put(path, dat, "t:"+tm)

	dat2 = b.runCmdToBytes(t, "kv", "get", "--force-output", "-t", tm,
		path, "-")
	require.Equal(t, dat, dat2)

	// shut down the REST server
	b.runCmd(t, nil, "kv", "rest", "stop")
}
