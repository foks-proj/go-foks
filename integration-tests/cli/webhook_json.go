// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

const paymentSuccessWebhookJson = `
{
  "id": "{{ .EventID }}",
  "object": "event",
  "api_version": "2025-03-31.basil",
  "created": {{ .TimeCreated }},
  "data": {
    "object": {
      "id": "{{ .InvoiceID }}",
      "object": "invoice",
      "account_country": "US",
      "account_name": "NE43 INC",
      "account_tax_ids": null,
      "amount_due": 190,
      "amount_overpaid": 0,
      "amount_paid": 190,
      "amount_remaining": 0,
      "amount_shipping": 0,
      "application": null,
      "attempt_count": 1,
      "attempted": true,
      "auto_advance": false,
      "automatic_tax": {
        "disabled_reason": null,
        "enabled": false,
        "liability": null,
        "provider": null,
        "status": null
      },
      "automatically_finalizes_at": null,
      "billing_reason": "subscription_create",
      "collection_method": "charge_automatically",
      "created": {{ .TimeCreated }},
      "currency": "usd",
      "custom_fields": null,
      "customer": "{{ .CustomerID }}",
      "customer_address": null,
      "customer_email": "{{ .Email }}",
      "customer_name": null,
      "customer_phone": null,
      "customer_shipping": null,
      "customer_tax_exempt": "none",
      "customer_tax_ids": [],
      "default_payment_method": null,
      "default_source": null,
      "default_tax_rates": [],
      "description": null,
      "discounts": [],
      "due_date": null,
      "effective_at": {{ .TimeCreated }},
      "ending_balance": 0,
      "footer": null,
      "from_invoice": null,
      "hosted_invoice_url": "https://invoice.stripe.com/i/acct_1PykJVP3NyTLHrvd/test_YWNjdF8xUHlrSlZQM055VExIcnZkLF9RdVpURk5EM1RHM0Uxck9aZkQwWk0xNUxjdVhPS0tvLDExNzc2OTY4Nw0200aoSXoSAo?s=ap",
      "invoice_pdf": "https://pay.stripe.com/invoice/acct_1PykJVP3NyTLHrvd/test_YWNjdF8xUHlrSlZQM055VExIcnZkLF9RdVpURk5EM1RHM0Uxck9aZkQwWk0xNUxjdVhPS0tvLDExNzc2OTY4Nw0200aoSXoSAo/pdf?s=ap",
      "issuer": {
        "type": "self"
      },
      "last_finalization_error": null,
      "latest_revision": null,
      "lines": {
        "object": "list",
        "data": [
          {
            "id": "{{ .IlID }}",
            "object": "line_item",
            "amount": {{ .Amount }},
            "currency": "usd",
            "description": "1 × Dingo 2 Eta (at $0.95 / day)",
            "discount_amounts": [],
            "discountable": true,
            "discounts": [],
            "invoice": "{{ .InvoiceID }}",
            "livemode": true,
            "metadata": {},
            "parent": {
              "invoice_item_details": null,
              "subscription_item_details": {
                "invoice_item": null,
                "proration": false,
                "proration_details": {
                  "credited_items": null
                },
                "subscription": "{{ .SubscriptionID }}",
                "subscription_item": "{{ .SubscriptionItemID }}"
              },
              "type": "subscription_item_details"
            },
            "period": {
              "end": {{ .PeriodEnd }},
              "start": {{ .PeriodStart }}
            },
            "pretax_credit_amounts": [],
            "pricing": {
              "price_details": {
                "price": "{{ .PriceID }}",
                "product": "{{ .PlanID }}"
              },
              "type": "price_details",
              "unit_amount_decimal": "{{ .AmountDecimal }}"
            },
            "quantity": 1,
            "taxes": []
          }
        ],
        "has_more": false,
        "total_count": 1,
        "url": "/v1/invoices/{{ .InvoiceID }}/lines"
      },
      "livemode": true,
      "metadata": {},
      "next_payment_attempt": null,
      "number": "E4SH3PJZ-0001",
      "on_behalf_of": null,
      "parent": {
        "quote_details": null,
        "subscription_details": {
          "metadata": {},
          "subscription": "{{ .SubscriptionID }}"
        },
        "type": "subscription_details"
      },
      "payment_settings": {
        "default_mandate": null,
        "payment_method_options": {
          "acss_debit": null,
          "bancontact": null,
          "card": {
            "request_three_d_secure": "automatic"
          },
          "customer_balance": null,
          "konbini": null,
          "sepa_debit": null,
          "us_bank_account": null
        },
        "payment_method_types": null
      },
      "period_end": {{ .TimeCreated }},
      "period_start": {{ .TimeCreated }},
      "post_payment_credit_notes_amount": 0,
      "pre_payment_credit_notes_amount": 0,
      "receipt_number": null,
      "rendering": null,
      "shipping_cost": null,
      "shipping_details": null,
      "starting_balance": 0,
      "statement_descriptor": null,
      "status": "paid",
      "status_transitions": {
        "finalized_at": {{ .TimeCreated }},
        "marked_uncollectible_at": null,
        "paid_at": {{ .TimeCreated }},
        "voided_at": null
      },
      "subtotal": {{ .Amount }},
      "subtotal_excluding_tax": {{ .Amount }},
      "test_clock": null,
      "total": {{ .Amount }},
      "total_discount_amounts": [],
      "total_excluding_tax": {{ .Amount }},
      "total_pretax_credit_amounts": [],
      "total_taxes": [],
      "webhooks_delivered_at": {{ .TimeCreated }}
    }
  },
  "livemode": false,
  "pending_webhooks": 1,
  "request": {
    "id": null,
    "idempotency_key": "6f5f0837-c8fd-4c2e-93ae-94d85f42f668"
  },
  "type": "invoice.payment_succeeded"
}`
