// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package licensemanager

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Top Utilized Product Licenses in Oracle Cloud Infrastructure License Manager service.
//
// Retrieves the top utilized product licenses for a given compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/licensemanager"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := licensemanager.GetTopUtilizedProductLicenses(ctx, &licensemanager.GetTopUtilizedProductLicensesArgs{
//				CompartmentId:            compartmentId,
//				IsCompartmentIdInSubtree: pulumi.BoolRef(topUtilizedProductLicenseIsCompartmentIdInSubtree),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetTopUtilizedProductLicenses(ctx *pulumi.Context, args *GetTopUtilizedProductLicensesArgs, opts ...pulumi.InvokeOption) (*GetTopUtilizedProductLicensesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetTopUtilizedProductLicensesResult
	err := ctx.Invoke("oci:LicenseManager/getTopUtilizedProductLicenses:getTopUtilizedProductLicenses", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getTopUtilizedProductLicenses.
type GetTopUtilizedProductLicensesArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
	CompartmentId string `pulumi:"compartmentId"`
	// Indicates if the given compartment is the root compartment.
	IsCompartmentIdInSubtree *bool `pulumi:"isCompartmentIdInSubtree"`
}

// A collection of values returned by getTopUtilizedProductLicenses.
type GetTopUtilizedProductLicensesResult struct {
	CompartmentId string `pulumi:"compartmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id                       string `pulumi:"id"`
	IsCompartmentIdInSubtree *bool  `pulumi:"isCompartmentIdInSubtree"`
	// Collection of top utilized product licenses.
	Items []GetTopUtilizedProductLicensesItem `pulumi:"items"`
}

func GetTopUtilizedProductLicensesOutput(ctx *pulumi.Context, args GetTopUtilizedProductLicensesOutputArgs, opts ...pulumi.InvokeOption) GetTopUtilizedProductLicensesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetTopUtilizedProductLicensesResultOutput, error) {
			args := v.(GetTopUtilizedProductLicensesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:LicenseManager/getTopUtilizedProductLicenses:getTopUtilizedProductLicenses", args, GetTopUtilizedProductLicensesResultOutput{}, options).(GetTopUtilizedProductLicensesResultOutput), nil
		}).(GetTopUtilizedProductLicensesResultOutput)
}

// A collection of arguments for invoking getTopUtilizedProductLicenses.
type GetTopUtilizedProductLicensesOutputArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Indicates if the given compartment is the root compartment.
	IsCompartmentIdInSubtree pulumi.BoolPtrInput `pulumi:"isCompartmentIdInSubtree"`
}

func (GetTopUtilizedProductLicensesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetTopUtilizedProductLicensesArgs)(nil)).Elem()
}

// A collection of values returned by getTopUtilizedProductLicenses.
type GetTopUtilizedProductLicensesResultOutput struct{ *pulumi.OutputState }

func (GetTopUtilizedProductLicensesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetTopUtilizedProductLicensesResult)(nil)).Elem()
}

func (o GetTopUtilizedProductLicensesResultOutput) ToGetTopUtilizedProductLicensesResultOutput() GetTopUtilizedProductLicensesResultOutput {
	return o
}

func (o GetTopUtilizedProductLicensesResultOutput) ToGetTopUtilizedProductLicensesResultOutputWithContext(ctx context.Context) GetTopUtilizedProductLicensesResultOutput {
	return o
}

func (o GetTopUtilizedProductLicensesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetTopUtilizedProductLicensesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetTopUtilizedProductLicensesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetTopUtilizedProductLicensesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetTopUtilizedProductLicensesResultOutput) IsCompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetTopUtilizedProductLicensesResult) *bool { return v.IsCompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

// Collection of top utilized product licenses.
func (o GetTopUtilizedProductLicensesResultOutput) Items() GetTopUtilizedProductLicensesItemArrayOutput {
	return o.ApplyT(func(v GetTopUtilizedProductLicensesResult) []GetTopUtilizedProductLicensesItem { return v.Items }).(GetTopUtilizedProductLicensesItemArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetTopUtilizedProductLicensesResultOutput{})
}
