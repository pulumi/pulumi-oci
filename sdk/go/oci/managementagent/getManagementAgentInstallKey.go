// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package managementagent

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Management Agent Install Key resource in Oracle Cloud Infrastructure Management Agent service.
//
// # Gets complete details of the Agent install Key for a given key id
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/managementagent"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := managementagent.GetManagementAgentInstallKey(ctx, &managementagent.GetManagementAgentInstallKeyArgs{
//				ManagementAgentInstallKeyId: testManagementAgentInstallKeyOciManagementAgentManagementAgentInstallKey.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupManagementAgentInstallKey(ctx *pulumi.Context, args *LookupManagementAgentInstallKeyArgs, opts ...pulumi.InvokeOption) (*LookupManagementAgentInstallKeyResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupManagementAgentInstallKeyResult
	err := ctx.Invoke("oci:ManagementAgent/getManagementAgentInstallKey:getManagementAgentInstallKey", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagementAgentInstallKey.
type LookupManagementAgentInstallKeyArgs struct {
	// Unique Management Agent Install Key identifier
	ManagementAgentInstallKeyId string `pulumi:"managementAgentInstallKeyId"`
}

// A collection of values returned by getManagementAgentInstallKey.
type LookupManagementAgentInstallKeyResult struct {
	// Total number of install for this keys
	AllowedKeyInstallCount int `pulumi:"allowedKeyInstallCount"`
	// Compartment Identifier
	CompartmentId string `pulumi:"compartmentId"`
	// Principal id of user who created the Agent Install key
	CreatedByPrincipalId string `pulumi:"createdByPrincipalId"`
	// Total number of install for this keys
	CurrentKeyInstallCount int `pulumi:"currentKeyInstallCount"`
	// Management Agent Install Key Name
	DisplayName string `pulumi:"displayName"`
	// Agent install Key identifier
	Id string `pulumi:"id"`
	// If set to true, the install key has no expiration date or usage limit. Properties allowedKeyInstallCount and timeExpires are ignored if set to true. Defaults to false.
	IsUnlimited bool `pulumi:"isUnlimited"`
	// Management Agent Install Key
	Key string `pulumi:"key"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails            string `pulumi:"lifecycleDetails"`
	ManagementAgentInstallKeyId string `pulumi:"managementAgentInstallKeyId"`
	// Status of Key
	State string `pulumi:"state"`
	// The time when Management Agent install Key was created. An RFC3339 formatted date time string
	TimeCreated string `pulumi:"timeCreated"`
	// date after which key would expire after creation
	TimeExpires string `pulumi:"timeExpires"`
	// The time when Management Agent install Key was updated. An RFC3339 formatted date time string
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupManagementAgentInstallKeyOutput(ctx *pulumi.Context, args LookupManagementAgentInstallKeyOutputArgs, opts ...pulumi.InvokeOption) LookupManagementAgentInstallKeyResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupManagementAgentInstallKeyResultOutput, error) {
			args := v.(LookupManagementAgentInstallKeyArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ManagementAgent/getManagementAgentInstallKey:getManagementAgentInstallKey", args, LookupManagementAgentInstallKeyResultOutput{}, options).(LookupManagementAgentInstallKeyResultOutput), nil
		}).(LookupManagementAgentInstallKeyResultOutput)
}

// A collection of arguments for invoking getManagementAgentInstallKey.
type LookupManagementAgentInstallKeyOutputArgs struct {
	// Unique Management Agent Install Key identifier
	ManagementAgentInstallKeyId pulumi.StringInput `pulumi:"managementAgentInstallKeyId"`
}

func (LookupManagementAgentInstallKeyOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupManagementAgentInstallKeyArgs)(nil)).Elem()
}

// A collection of values returned by getManagementAgentInstallKey.
type LookupManagementAgentInstallKeyResultOutput struct{ *pulumi.OutputState }

func (LookupManagementAgentInstallKeyResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupManagementAgentInstallKeyResult)(nil)).Elem()
}

func (o LookupManagementAgentInstallKeyResultOutput) ToLookupManagementAgentInstallKeyResultOutput() LookupManagementAgentInstallKeyResultOutput {
	return o
}

func (o LookupManagementAgentInstallKeyResultOutput) ToLookupManagementAgentInstallKeyResultOutputWithContext(ctx context.Context) LookupManagementAgentInstallKeyResultOutput {
	return o
}

// Total number of install for this keys
func (o LookupManagementAgentInstallKeyResultOutput) AllowedKeyInstallCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) int { return v.AllowedKeyInstallCount }).(pulumi.IntOutput)
}

// Compartment Identifier
func (o LookupManagementAgentInstallKeyResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Principal id of user who created the Agent Install key
func (o LookupManagementAgentInstallKeyResultOutput) CreatedByPrincipalId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) string { return v.CreatedByPrincipalId }).(pulumi.StringOutput)
}

// Total number of install for this keys
func (o LookupManagementAgentInstallKeyResultOutput) CurrentKeyInstallCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) int { return v.CurrentKeyInstallCount }).(pulumi.IntOutput)
}

// Management Agent Install Key Name
func (o LookupManagementAgentInstallKeyResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Agent install Key identifier
func (o LookupManagementAgentInstallKeyResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) string { return v.Id }).(pulumi.StringOutput)
}

// If set to true, the install key has no expiration date or usage limit. Properties allowedKeyInstallCount and timeExpires are ignored if set to true. Defaults to false.
func (o LookupManagementAgentInstallKeyResultOutput) IsUnlimited() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) bool { return v.IsUnlimited }).(pulumi.BoolOutput)
}

// Management Agent Install Key
func (o LookupManagementAgentInstallKeyResultOutput) Key() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) string { return v.Key }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o LookupManagementAgentInstallKeyResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

func (o LookupManagementAgentInstallKeyResultOutput) ManagementAgentInstallKeyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) string { return v.ManagementAgentInstallKeyId }).(pulumi.StringOutput)
}

// Status of Key
func (o LookupManagementAgentInstallKeyResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) string { return v.State }).(pulumi.StringOutput)
}

// The time when Management Agent install Key was created. An RFC3339 formatted date time string
func (o LookupManagementAgentInstallKeyResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// date after which key would expire after creation
func (o LookupManagementAgentInstallKeyResultOutput) TimeExpires() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) string { return v.TimeExpires }).(pulumi.StringOutput)
}

// The time when Management Agent install Key was updated. An RFC3339 formatted date time string
func (o LookupManagementAgentInstallKeyResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementAgentInstallKeyResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupManagementAgentInstallKeyResultOutput{})
}
