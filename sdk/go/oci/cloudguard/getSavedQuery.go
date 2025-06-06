// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudguard

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Saved Query resource in Oracle Cloud Infrastructure Cloud Guard service.
//
// Returns a SavedQuery resource identified by savedQueryId.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/cloudguard"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := cloudguard.GetSavedQuery(ctx, &cloudguard.GetSavedQueryArgs{
//				SavedQueryId: testSavedQueryOciCloudGuardSavedQuery.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupSavedQuery(ctx *pulumi.Context, args *LookupSavedQueryArgs, opts ...pulumi.InvokeOption) (*LookupSavedQueryResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupSavedQueryResult
	err := ctx.Invoke("oci:CloudGuard/getSavedQuery:getSavedQuery", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSavedQuery.
type LookupSavedQueryArgs struct {
	// Saved query OCID
	SavedQueryId string `pulumi:"savedQueryId"`
}

// A collection of values returned by getSavedQuery.
type LookupSavedQueryResult struct {
	// Compartment OCID of the saved query
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Description of the saved query
	Description string `pulumi:"description"`
	// Display name of the saved query
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// OCID for the saved query
	Id string `pulumi:"id"`
	// The saved query expression
	Query        string `pulumi:"query"`
	SavedQueryId string `pulumi:"savedQueryId"`
	// The current lifecycle state of the resource
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the saved query was created. Format defined by RFC3339.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the saved query was updated. Format defined by RFC3339.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupSavedQueryOutput(ctx *pulumi.Context, args LookupSavedQueryOutputArgs, opts ...pulumi.InvokeOption) LookupSavedQueryResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupSavedQueryResultOutput, error) {
			args := v.(LookupSavedQueryArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:CloudGuard/getSavedQuery:getSavedQuery", args, LookupSavedQueryResultOutput{}, options).(LookupSavedQueryResultOutput), nil
		}).(LookupSavedQueryResultOutput)
}

// A collection of arguments for invoking getSavedQuery.
type LookupSavedQueryOutputArgs struct {
	// Saved query OCID
	SavedQueryId pulumi.StringInput `pulumi:"savedQueryId"`
}

func (LookupSavedQueryOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSavedQueryArgs)(nil)).Elem()
}

// A collection of values returned by getSavedQuery.
type LookupSavedQueryResultOutput struct{ *pulumi.OutputState }

func (LookupSavedQueryResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSavedQueryResult)(nil)).Elem()
}

func (o LookupSavedQueryResultOutput) ToLookupSavedQueryResultOutput() LookupSavedQueryResultOutput {
	return o
}

func (o LookupSavedQueryResultOutput) ToLookupSavedQueryResultOutputWithContext(ctx context.Context) LookupSavedQueryResultOutput {
	return o
}

// Compartment OCID of the saved query
func (o LookupSavedQueryResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSavedQueryResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupSavedQueryResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupSavedQueryResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Description of the saved query
func (o LookupSavedQueryResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSavedQueryResult) string { return v.Description }).(pulumi.StringOutput)
}

// Display name of the saved query
func (o LookupSavedQueryResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSavedQueryResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupSavedQueryResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupSavedQueryResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// OCID for the saved query
func (o LookupSavedQueryResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSavedQueryResult) string { return v.Id }).(pulumi.StringOutput)
}

// The saved query expression
func (o LookupSavedQueryResultOutput) Query() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSavedQueryResult) string { return v.Query }).(pulumi.StringOutput)
}

func (o LookupSavedQueryResultOutput) SavedQueryId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSavedQueryResult) string { return v.SavedQueryId }).(pulumi.StringOutput)
}

// The current lifecycle state of the resource
func (o LookupSavedQueryResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSavedQueryResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupSavedQueryResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupSavedQueryResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the saved query was created. Format defined by RFC3339.
func (o LookupSavedQueryResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSavedQueryResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the saved query was updated. Format defined by RFC3339.
func (o LookupSavedQueryResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSavedQueryResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupSavedQueryResultOutput{})
}
