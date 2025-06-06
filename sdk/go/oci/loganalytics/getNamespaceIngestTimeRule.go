// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loganalytics

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Namespace Ingest Time Rule resource in Oracle Cloud Infrastructure Log Analytics service.
//
// Gets detailed information about the specified ingest time rule such as description, defined tags, and free-form tags.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/loganalytics"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := loganalytics.GetNamespaceIngestTimeRule(ctx, &loganalytics.GetNamespaceIngestTimeRuleArgs{
//				IngestTimeRuleId: testRule.Id,
//				Namespace:        namespaceIngestTimeRuleNamespace,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupNamespaceIngestTimeRule(ctx *pulumi.Context, args *LookupNamespaceIngestTimeRuleArgs, opts ...pulumi.InvokeOption) (*LookupNamespaceIngestTimeRuleResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupNamespaceIngestTimeRuleResult
	err := ctx.Invoke("oci:LogAnalytics/getNamespaceIngestTimeRule:getNamespaceIngestTimeRule", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNamespaceIngestTimeRule.
type LookupNamespaceIngestTimeRuleArgs struct {
	// Unique ocid of the ingest time rule.
	IngestTimeRuleId string `pulumi:"ingestTimeRuleId"`
	// The Logging Analytics namespace used for the request.
	Namespace string `pulumi:"namespace"`
}

// A collection of values returned by getNamespaceIngestTimeRule.
type LookupNamespaceIngestTimeRuleResult struct {
	// The action(s) to be performed if the ingest time rule condition(s) are satisfied.
	Actions []GetNamespaceIngestTimeRuleAction `pulumi:"actions"`
	// Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// The condition(s) to evaluate for an ingest time rule.
	Conditions []GetNamespaceIngestTimeRuleCondition `pulumi:"conditions"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Description for this resource.
	Description string `pulumi:"description"`
	// The ingest time rule display name.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The log analytics entity OCID. This ID is a reference used by log analytics features and it represents a resource that is provisioned and managed by the customer on their premises or on the cloud.
	Id               string `pulumi:"id"`
	IngestTimeRuleId string `pulumi:"ingestTimeRuleId"`
	// A flag indicating whether or not the ingest time rule is enabled.
	IsEnabled bool `pulumi:"isEnabled"`
	// The namespace of the extracted metric. A valid value starts with an alphabetical character and includes only alphanumeric characters and underscores (_).
	Namespace string `pulumi:"namespace"`
	// The current state of the ingest time rule.
	State string `pulumi:"state"`
	// The date and time the resource was created, in the format defined by RFC3339.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the resource was last updated, in the format defined by RFC3339.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupNamespaceIngestTimeRuleOutput(ctx *pulumi.Context, args LookupNamespaceIngestTimeRuleOutputArgs, opts ...pulumi.InvokeOption) LookupNamespaceIngestTimeRuleResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupNamespaceIngestTimeRuleResultOutput, error) {
			args := v.(LookupNamespaceIngestTimeRuleArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:LogAnalytics/getNamespaceIngestTimeRule:getNamespaceIngestTimeRule", args, LookupNamespaceIngestTimeRuleResultOutput{}, options).(LookupNamespaceIngestTimeRuleResultOutput), nil
		}).(LookupNamespaceIngestTimeRuleResultOutput)
}

// A collection of arguments for invoking getNamespaceIngestTimeRule.
type LookupNamespaceIngestTimeRuleOutputArgs struct {
	// Unique ocid of the ingest time rule.
	IngestTimeRuleId pulumi.StringInput `pulumi:"ingestTimeRuleId"`
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringInput `pulumi:"namespace"`
}

func (LookupNamespaceIngestTimeRuleOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNamespaceIngestTimeRuleArgs)(nil)).Elem()
}

// A collection of values returned by getNamespaceIngestTimeRule.
type LookupNamespaceIngestTimeRuleResultOutput struct{ *pulumi.OutputState }

func (LookupNamespaceIngestTimeRuleResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNamespaceIngestTimeRuleResult)(nil)).Elem()
}

func (o LookupNamespaceIngestTimeRuleResultOutput) ToLookupNamespaceIngestTimeRuleResultOutput() LookupNamespaceIngestTimeRuleResultOutput {
	return o
}

func (o LookupNamespaceIngestTimeRuleResultOutput) ToLookupNamespaceIngestTimeRuleResultOutputWithContext(ctx context.Context) LookupNamespaceIngestTimeRuleResultOutput {
	return o
}

// The action(s) to be performed if the ingest time rule condition(s) are satisfied.
func (o LookupNamespaceIngestTimeRuleResultOutput) Actions() GetNamespaceIngestTimeRuleActionArrayOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) []GetNamespaceIngestTimeRuleAction { return v.Actions }).(GetNamespaceIngestTimeRuleActionArrayOutput)
}

// Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
func (o LookupNamespaceIngestTimeRuleResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The condition(s) to evaluate for an ingest time rule.
func (o LookupNamespaceIngestTimeRuleResultOutput) Conditions() GetNamespaceIngestTimeRuleConditionArrayOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) []GetNamespaceIngestTimeRuleCondition { return v.Conditions }).(GetNamespaceIngestTimeRuleConditionArrayOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupNamespaceIngestTimeRuleResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Description for this resource.
func (o LookupNamespaceIngestTimeRuleResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) string { return v.Description }).(pulumi.StringOutput)
}

// The ingest time rule display name.
func (o LookupNamespaceIngestTimeRuleResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupNamespaceIngestTimeRuleResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The log analytics entity OCID. This ID is a reference used by log analytics features and it represents a resource that is provisioned and managed by the customer on their premises or on the cloud.
func (o LookupNamespaceIngestTimeRuleResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupNamespaceIngestTimeRuleResultOutput) IngestTimeRuleId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) string { return v.IngestTimeRuleId }).(pulumi.StringOutput)
}

// A flag indicating whether or not the ingest time rule is enabled.
func (o LookupNamespaceIngestTimeRuleResultOutput) IsEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) bool { return v.IsEnabled }).(pulumi.BoolOutput)
}

// The namespace of the extracted metric. A valid value starts with an alphabetical character and includes only alphanumeric characters and underscores (_).
func (o LookupNamespaceIngestTimeRuleResultOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) string { return v.Namespace }).(pulumi.StringOutput)
}

// The current state of the ingest time rule.
func (o LookupNamespaceIngestTimeRuleResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the resource was created, in the format defined by RFC3339.
func (o LookupNamespaceIngestTimeRuleResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the resource was last updated, in the format defined by RFC3339.
func (o LookupNamespaceIngestTimeRuleResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNamespaceIngestTimeRuleResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupNamespaceIngestTimeRuleResultOutput{})
}
