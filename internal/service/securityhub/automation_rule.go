// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package securityhub

import (
	"context"

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
			// "action":   actionSetNestedBlock,
			// "rule_enabled": {
			// 	Type:     schema.TypeBool,
			// 	Default:  true,
			// 	Optional: true,
			// },
			// "rule_order": {
			// 	Type:     schema.TypeInt,
			// 	Default:  1,
			// 	Optional: true,
			// },
			// "is_terminal": {
			// 	Type:     schema.TypeBool,
			// 	Optional: true,
			// },
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
			// "values": {
			// 	Type:     schema.TypeList,
			// 	Required: true,
			// 	MinItems: 1, // ça marche ou pas ?
			// 	Elem:
			// },
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
			// "types": {
			// 	Type:     schema.TypeList,
			// 	Optional: true,
			// },
			"note": {
				Type:     schema.TypeString,
				Optional: true,
			},
			// TODO Map for user_defined_fields
			// "user_defined_fields": {
			// 	Type:     schema.TypeList,
			// 	Required: true,
			// },
		},
	}
)

func resourceAutomationRuleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).SecurityHubConn(ctx)

	// rule_name := d.Get("rule_name").(string)
	// d.SetId("id")
	// d.Set("rule_name", "rule_name")
	// d.Set("description", "description")

	// log.Printf("[DEBUG] Creating Security Hub automation rule %s", rule_name)

	// func (c *SecurityHub) CreateAutomationRuleWithContext(ctx aws.Context, input *CreateAutomationRuleInput, opts ...request.Option) (*CreateAutomationRuleOutput, error)

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
		RuleName:    aws.String(d.Get("rule_name").(string)),
		RuleOrder:   aws.Int64(d.Get("rule_order").(int64)),
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

	// conn := meta.(*conns.AWSClient).SecurityHubConn(ctx)

	// aggregatorArn := d.Id()

	// log.Printf("[DEBUG] Reading Security Hub automation rule to find %s", aggregatorArn)

	// aggregator, err := AutomationRuleCheckExists(ctx, conn, aggregatorArn)

	// if err != nil {
	// 	return sdkdiag.AppendErrorf(diags, "reading Security Hub automation rule to find %s: %s", aggregatorArn, err)
	// }

	// if aggregator == nil {
	// 	log.Printf("[WARN] Security Hub automation rule (%s) not found, removing from state", aggregatorArn)
	// 	d.SetId("")
	// 	return diags
	// }

	// d.Set("linking_mode", aggregator.RegionLinkingMode)

	// if len(aggregator.Regions) > 0 {
	// 	d.Set("specified_regions", flex.FlattenStringList(aggregator.Regions))
	// }

	return diags
}

//func AutomationRuleCheckExists(ctx context.Context, conn *securityhub.SecurityHub, automationRuleArn string) (*securityhub.GetAutomationRuleOutput, error) {
// 	input := &securityhub.ListAutomationRulesInput{}

// 	var found *securityhub.GetAutomationRuleOutput
// 	var err error

// 	err = conn.ListAutomationRulesPagesWithContext(ctx, input, func(page *securityhub.ListAutomationRulesOutput, lastPage bool) bool {
// 		for _, aggregator := range page.AutomationRules {
// 			if aws.StringValue(aggregator.AutomationRuleArn) == automationRuleArn {
// 				getInput := &securityhub.GetAutomationRuleInput{
// 					AutomationRuleArn: &automationRuleArn,
// 				}
// 				found, err = conn.GetAutomationRuleWithContext(ctx, getInput)
// 				return false
// 			}
// 		}
// 		return !lastPage
// 	})

// 	if err != nil {
// 		return nil, err
// 	}

// 	return found, nil
//}

func resourceAutomationRuleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

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
	// conn := meta.(*conns.AWSClient).SecurityHubConn(ctx)

	// aggregatorArn := d.Id()

	// log.Printf("[DEBUG] Disabling Security Hub automation rule %s", aggregatorArn)

	// _, err := conn.DeleteAutomationRuleWithContext(ctx, &securityhub.DeleteAutomationRuleInput{
	// 	AutomationRuleArn: &aggregatorArn,
	// })

	// if err != nil {
	// 	return sdkdiag.AppendErrorf(diags, "disabling Security Hub automation rule %s: %s", aggregatorArn, err)
	// }

	return diags
}
