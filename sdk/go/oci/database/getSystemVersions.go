// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of System Versions in Oracle Cloud Infrastructure Database service.
//
// Gets a list of supported Exadata system versions for a given shape and GI version.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := database.GetSystemVersions(ctx, &database.GetSystemVersionsArgs{
//				CompartmentId: compartmentId,
//				GiVersion:     systemVersionGiVersion,
//				Shape:         systemVersionShape,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSystemVersions(ctx *pulumi.Context, args *GetSystemVersionsArgs, opts ...pulumi.InvokeOption) (*GetSystemVersionsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetSystemVersionsResult
	err := ctx.Invoke("oci:Database/getSystemVersions:getSystemVersions", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSystemVersions.
type GetSystemVersionsArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string                    `pulumi:"compartmentId"`
	Filters       []GetSystemVersionsFilter `pulumi:"filters"`
	// Specifies gi version query parameter.
	GiVersion string `pulumi:"giVersion"`
	// Specifies shape query parameter.
	Shape string `pulumi:"shape"`
}

// A collection of values returned by getSystemVersions.
type GetSystemVersionsResult struct {
	CompartmentId string                    `pulumi:"compartmentId"`
	Filters       []GetSystemVersionsFilter `pulumi:"filters"`
	// Grid Infrastructure version.
	GiVersion string `pulumi:"giVersion"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Exadata shape.
	Shape string `pulumi:"shape"`
	// The list of system_version_collection.
	SystemVersionCollections []GetSystemVersionsSystemVersionCollection `pulumi:"systemVersionCollections"`
}

func GetSystemVersionsOutput(ctx *pulumi.Context, args GetSystemVersionsOutputArgs, opts ...pulumi.InvokeOption) GetSystemVersionsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetSystemVersionsResultOutput, error) {
			args := v.(GetSystemVersionsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getSystemVersions:getSystemVersions", args, GetSystemVersionsResultOutput{}, options).(GetSystemVersionsResultOutput), nil
		}).(GetSystemVersionsResultOutput)
}

// A collection of arguments for invoking getSystemVersions.
type GetSystemVersionsOutputArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput                `pulumi:"compartmentId"`
	Filters       GetSystemVersionsFilterArrayInput `pulumi:"filters"`
	// Specifies gi version query parameter.
	GiVersion pulumi.StringInput `pulumi:"giVersion"`
	// Specifies shape query parameter.
	Shape pulumi.StringInput `pulumi:"shape"`
}

func (GetSystemVersionsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSystemVersionsArgs)(nil)).Elem()
}

// A collection of values returned by getSystemVersions.
type GetSystemVersionsResultOutput struct{ *pulumi.OutputState }

func (GetSystemVersionsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSystemVersionsResult)(nil)).Elem()
}

func (o GetSystemVersionsResultOutput) ToGetSystemVersionsResultOutput() GetSystemVersionsResultOutput {
	return o
}

func (o GetSystemVersionsResultOutput) ToGetSystemVersionsResultOutputWithContext(ctx context.Context) GetSystemVersionsResultOutput {
	return o
}

func (o GetSystemVersionsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSystemVersionsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetSystemVersionsResultOutput) Filters() GetSystemVersionsFilterArrayOutput {
	return o.ApplyT(func(v GetSystemVersionsResult) []GetSystemVersionsFilter { return v.Filters }).(GetSystemVersionsFilterArrayOutput)
}

// Grid Infrastructure version.
func (o GetSystemVersionsResultOutput) GiVersion() pulumi.StringOutput {
	return o.ApplyT(func(v GetSystemVersionsResult) string { return v.GiVersion }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSystemVersionsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSystemVersionsResult) string { return v.Id }).(pulumi.StringOutput)
}

// Exadata shape.
func (o GetSystemVersionsResultOutput) Shape() pulumi.StringOutput {
	return o.ApplyT(func(v GetSystemVersionsResult) string { return v.Shape }).(pulumi.StringOutput)
}

// The list of system_version_collection.
func (o GetSystemVersionsResultOutput) SystemVersionCollections() GetSystemVersionsSystemVersionCollectionArrayOutput {
	return o.ApplyT(func(v GetSystemVersionsResult) []GetSystemVersionsSystemVersionCollection {
		return v.SystemVersionCollections
	}).(GetSystemVersionsSystemVersionCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSystemVersionsResultOutput{})
}
