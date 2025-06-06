// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mysql

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Channel resource in Oracle Cloud Infrastructure MySQL Database service.
//
// Gets the full details of the specified Channel, including the user-specified
// configuration parameters (passwords are omitted), as well as information about
// the state of the Channel, its sources and targets.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/mysql"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := mysql.GetChannel(ctx, &mysql.GetChannelArgs{
//				ChannelId: testChannelOciMysqlChannel.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupChannel(ctx *pulumi.Context, args *LookupChannelArgs, opts ...pulumi.InvokeOption) (*LookupChannelResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupChannelResult
	err := ctx.Invoke("oci:Mysql/getChannel:getChannel", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getChannel.
type LookupChannelArgs struct {
	// The Channel [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ChannelId string `pulumi:"channelId"`
}

// A collection of values returned by getChannel.
type LookupChannelResult struct {
	ChannelId string `pulumi:"channelId"`
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// User provided description of the Channel.
	Description string `pulumi:"description"`
	// The user-friendly name for the Channel. It does not have to be unique.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	Id           string            `pulumi:"id"`
	// Whether the Channel has been enabled by the user.
	IsEnabled bool `pulumi:"isEnabled"`
	// A message describing the state of the Channel.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Parameters detailing how to provision the source for the given Channel.
	Sources []GetChannelSource `pulumi:"sources"`
	// The state of the Channel.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// Details about the Channel target.
	Targets []GetChannelTarget `pulumi:"targets"`
	// The date and time the Channel was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
	TimeCreated string `pulumi:"timeCreated"`
	// The time the Channel was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupChannelOutput(ctx *pulumi.Context, args LookupChannelOutputArgs, opts ...pulumi.InvokeOption) LookupChannelResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupChannelResultOutput, error) {
			args := v.(LookupChannelArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Mysql/getChannel:getChannel", args, LookupChannelResultOutput{}, options).(LookupChannelResultOutput), nil
		}).(LookupChannelResultOutput)
}

// A collection of arguments for invoking getChannel.
type LookupChannelOutputArgs struct {
	// The Channel [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ChannelId pulumi.StringInput `pulumi:"channelId"`
}

func (LookupChannelOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupChannelArgs)(nil)).Elem()
}

// A collection of values returned by getChannel.
type LookupChannelResultOutput struct{ *pulumi.OutputState }

func (LookupChannelResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupChannelResult)(nil)).Elem()
}

func (o LookupChannelResultOutput) ToLookupChannelResultOutput() LookupChannelResultOutput {
	return o
}

func (o LookupChannelResultOutput) ToLookupChannelResultOutputWithContext(ctx context.Context) LookupChannelResultOutput {
	return o
}

func (o LookupChannelResultOutput) ChannelId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupChannelResult) string { return v.ChannelId }).(pulumi.StringOutput)
}

// The OCID of the compartment.
func (o LookupChannelResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupChannelResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupChannelResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupChannelResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// User provided description of the Channel.
func (o LookupChannelResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupChannelResult) string { return v.Description }).(pulumi.StringOutput)
}

// The user-friendly name for the Channel. It does not have to be unique.
func (o LookupChannelResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupChannelResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupChannelResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupChannelResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

func (o LookupChannelResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupChannelResult) string { return v.Id }).(pulumi.StringOutput)
}

// Whether the Channel has been enabled by the user.
func (o LookupChannelResultOutput) IsEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupChannelResult) bool { return v.IsEnabled }).(pulumi.BoolOutput)
}

// A message describing the state of the Channel.
func (o LookupChannelResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupChannelResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Parameters detailing how to provision the source for the given Channel.
func (o LookupChannelResultOutput) Sources() GetChannelSourceArrayOutput {
	return o.ApplyT(func(v LookupChannelResult) []GetChannelSource { return v.Sources }).(GetChannelSourceArrayOutput)
}

// The state of the Channel.
func (o LookupChannelResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupChannelResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupChannelResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupChannelResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// Details about the Channel target.
func (o LookupChannelResultOutput) Targets() GetChannelTargetArrayOutput {
	return o.ApplyT(func(v LookupChannelResult) []GetChannelTarget { return v.Targets }).(GetChannelTargetArrayOutput)
}

// The date and time the Channel was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
func (o LookupChannelResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupChannelResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the Channel was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
func (o LookupChannelResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupChannelResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupChannelResultOutput{})
}
