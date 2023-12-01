// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package securityhub

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
)

// @SDKResource("aws_securityhub_automation_rule")
func ResourceAutomationRule() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceAutomationRuleCreate,
		UpdateWithoutTimeout: resourceAutomationRuleUpdate,
		ReadWithoutTimeout:   resourceAutomationRuleRead,
		DeleteWithoutTimeout: resourceAutomationRuleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"rule_name": {
				Type:     schema.TypeString,
				Required: true,
				// ForceNew:     true,
			},
			"description": {
				Type:     schema.TypeString,
				Required: true,
				// ForceNew: true,
			},
			// "criteria": criteriaSetNestedBlock,
			// "action": actionSetNestedBlock,
			"rule_enabled": {
				Type:     schema.TypeBool,
				Default:  true,
				Optional: true,
			},
			"rule_order": {
				Type:     schema.TypeInt,
				Default:  1,
				Optional: true,
			},
			"is_terminal": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
		},
	}
}

var (
	criteriaSetNestedBlock = &schema.Schema{
		Type:       schema.TypeSet,
		Required:   true,
		ConfigMode: schema.SchemaConfigModeAttr,
		Elem:       criteriaNestedBlock,
	}

	criteriaNestedBlock = &schema.Resource{
		Schema: map[string]*schema.Schema{
			"key": {
				Type:     schema.TypeString,
				Required: true,
				// TODO ValidateFunc: validCriteriaKey,
			},
			"operator": {
				Type:     schema.TypeString,
				Optional: true,
				// TODO ValidateFunc: validOperator
			},
			"values": {
				Type:     schema.TypeList,
				Required: true,
				MinItems: 1,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
)

var (
	actionSetNestedBlock = &schema.Schema{
		Type:       schema.TypeSet,
		Required:   true,
		ConfigMode: schema.SchemaConfigModeAttr,
		Elem:       actionNestedBlock,
	}

	actionNestedBlock = &schema.Resource{
		Schema: map[string]*schema.Schema{
			"workflow_status": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"severity": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"criticality": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"verification_state": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"confidence": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"types": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"note": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"user_defined_fields": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
)

func resourceAutomationRuleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).SecurityHubConn(ctx)

	log.Printf("[DEBUG] Creating Security Hub automation rule %s", d.Get("rule_name"))

	input := &securityhub.CreateAutomationRuleInput{
		// TODO: Handle actions and criterias
		Actions: []*securityhub.AutomationRulesAction{
			{
				FindingFieldsUpdate: &securityhub.AutomationRulesFindingFieldsUpdate{
					Criticality: aws.Int64(1),
				},
				Type: aws.String("FINDING_FIELDS_UPDATE"),
			},
		},
		Criteria: &securityhub.AutomationRulesFindingFilters{
			CompanyName: []*securityhub.StringFilter{
				{Comparison: aws.String("NOT_CONTAINS"), Value: aws.String("a")},
			},
		},
		Description: aws.String(d.Get("description").(string)),
		IsTerminal:  aws.Bool(d.Get("is_terminal").(bool)),
		RuleName:    aws.String(d.Get("rule_name").(string)),
		RuleOrder:   aws.Int64(int64(d.Get("rule_order").(int))),
		RuleStatus: aws.String(func() string {
			if d.Get("rule_enabled").(bool) {
				return "ENABLED"
			}
			return "DISABLED"
		}()),
	}

	resp, err := conn.CreateAutomationRuleWithContext(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating automation rule for Security Hub: %s", err)
	}

	d.SetId(aws.StringValue(resp.RuleArn))

	return append(diags, resourceAutomationRuleRead(ctx, d, meta)...)
}

func resourceAutomationRuleRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).SecurityHubConn(ctx)

	aggregatorArn := d.Id()

	log.Printf("[DEBUG] Reading Security Hub automation rule to find %s", aggregatorArn)

	output, err := conn.BatchGetAutomationRulesWithContext(ctx, &securityhub.BatchGetAutomationRulesInput{
		AutomationRulesArns: []*string{
			&aggregatorArn,
		},
	})

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Security Hub automation rule to find %s: %s", aggregatorArn, err)
	}

	if len(output.Rules) == 0 {
		return sdkdiag.AppendErrorf(diags, "Security Hub automation rule %s not found. It seems that it has not been created correctly.", aggregatorArn)
	}

	return diags
}

func resourceAutomationRuleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	// conn := meta.(*conns.AWSClient).SecurityHubConn(ctx)

	// input := securityhub.BatchGetAutomationRulesInput {
	// 	AutomationRulesArns: []*string{d.Id()},
	// }

	return diags
	// 	conn := meta.(*conns.AWSClient).SecurityHubConn(ctx)

	// 	aggregatorArn := d.Id()

	// 	linkingMode := d.Get("linking_mode").(string)

	//	req := &securityhub.UpdateAutomationRuleInput{
	//		AutomationRuleArn: &aggregatorArn,
	//		RegionLinkingMode:    &linkingMode,
}

// 	if v, ok := d.GetOk("specified_regions"); ok && (linkingMode == allRegionsExceptSpecified || linkingMode == specifiedRegions) {
// 		req.Regions = flex.ExpandStringSet(v.(*schema.Set))
// 	}

// 	resp, err := conn.UpdateAutomationRuleWithContext(ctx, req)

// 	if err != nil {
// 		return sdkdiag.AppendErrorf(diags, "updating Security Hub automation rule (%s): %s", aggregatorArn, err)
// 	}

// 	d.SetId(aws.StringValue(resp.AutomationRuleArn))

// 	return append(diags, resourceAutomationRuleRead(ctx, d, meta)...)
// }

func resourceAutomationRuleDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).SecurityHubConn(ctx)

	automationRuleArn := d.Id()

	log.Printf("[DEBUG] Deleting Security Hub automation rule %s", automationRuleArn)

	_, err := conn.BatchDeleteAutomationRulesWithContext(ctx, &securityhub.BatchDeleteAutomationRulesInput{
		AutomationRulesArns: []*string{
			&automationRuleArn,
		},
	})

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "Deleting Security Hub automation rule %s: %s", automationRuleArn, err)
	}

	return diags
}
