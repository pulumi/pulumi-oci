// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Byoasn resource in Oracle Cloud Infrastructure Core service.
//
// Gets the `Byoasn` resource. You must specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.GetByoasn(ctx, &core.GetByoasnArgs{
//				ByoasnId: testByoasnOciCoreByoasn.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupByoasn(ctx *pulumi.Context, args *LookupByoasnArgs, opts ...pulumi.InvokeOption) (*LookupByoasnResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupByoasnResult
	err := ctx.Invoke("oci:Core/getByoasn:getByoasn", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getByoasn.
type LookupByoasnArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `Byoasn` resource.
	ByoasnId string `pulumi:"byoasnId"`
}

// A collection of values returned by getByoasn.
type LookupByoasnResult struct {
	// The Autonomous System Number (ASN) you are importing to the Oracle cloud.
	Asn      string `pulumi:"asn"`
	ByoasnId string `pulumi:"byoasnId"`
	// The BYOIP Ranges that has the `Byoasn` as origin.
	ByoipRanges []GetByoasnByoipRange `pulumi:"byoipRanges"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Byoasn` resource.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `Byoasn` resource.
	Id string `pulumi:"id"`
	// The `Byoasn` resource's current state.
	State string `pulumi:"state"`
	// The date and time the `Byoasn` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the `Byoasn` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated string `pulumi:"timeUpdated"`
	// The date and time the `Byoasn` resource was validated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeValidated string `pulumi:"timeValidated"`
	// The validation token is an internally-generated ASCII string used in the validation process. See [Importing a Byoasn](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/BYOASN.htm) for details.
	ValidationToken string `pulumi:"validationToken"`
}

func LookupByoasnOutput(ctx *pulumi.Context, args LookupByoasnOutputArgs, opts ...pulumi.InvokeOption) LookupByoasnResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupByoasnResultOutput, error) {
			args := v.(LookupByoasnArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getByoasn:getByoasn", args, LookupByoasnResultOutput{}, options).(LookupByoasnResultOutput), nil
		}).(LookupByoasnResultOutput)
}

// A collection of arguments for invoking getByoasn.
type LookupByoasnOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `Byoasn` resource.
	ByoasnId pulumi.StringInput `pulumi:"byoasnId"`
}

func (LookupByoasnOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupByoasnArgs)(nil)).Elem()
}

// A collection of values returned by getByoasn.
type LookupByoasnResultOutput struct{ *pulumi.OutputState }

func (LookupByoasnResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupByoasnResult)(nil)).Elem()
}

func (o LookupByoasnResultOutput) ToLookupByoasnResultOutput() LookupByoasnResultOutput {
	return o
}

func (o LookupByoasnResultOutput) ToLookupByoasnResultOutputWithContext(ctx context.Context) LookupByoasnResultOutput {
	return o
}

// The Autonomous System Number (ASN) you are importing to the Oracle cloud.
func (o LookupByoasnResultOutput) Asn() pulumi.StringOutput {
	return o.ApplyT(func(v LookupByoasnResult) string { return v.Asn }).(pulumi.StringOutput)
}

func (o LookupByoasnResultOutput) ByoasnId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupByoasnResult) string { return v.ByoasnId }).(pulumi.StringOutput)
}

// The BYOIP Ranges that has the `Byoasn` as origin.
func (o LookupByoasnResultOutput) ByoipRanges() GetByoasnByoipRangeArrayOutput {
	return o.ApplyT(func(v LookupByoasnResult) []GetByoasnByoipRange { return v.ByoipRanges }).(GetByoasnByoipRangeArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Byoasn` resource.
func (o LookupByoasnResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupByoasnResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o LookupByoasnResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupByoasnResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o LookupByoasnResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupByoasnResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupByoasnResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupByoasnResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `Byoasn` resource.
func (o LookupByoasnResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupByoasnResult) string { return v.Id }).(pulumi.StringOutput)
}

// The `Byoasn` resource's current state.
func (o LookupByoasnResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupByoasnResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the `Byoasn` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o LookupByoasnResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupByoasnResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the `Byoasn` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o LookupByoasnResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupByoasnResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The date and time the `Byoasn` resource was validated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o LookupByoasnResultOutput) TimeValidated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupByoasnResult) string { return v.TimeValidated }).(pulumi.StringOutput)
}

// The validation token is an internally-generated ASCII string used in the validation process. See [Importing a Byoasn](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/BYOASN.htm) for details.
func (o LookupByoasnResultOutput) ValidationToken() pulumi.StringOutput {
	return o.ApplyT(func(v LookupByoasnResult) string { return v.ValidationToken }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupByoasnResultOutput{})
}
