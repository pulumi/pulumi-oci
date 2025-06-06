// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Gi Version Minor Versions in Oracle Cloud Infrastructure Database service.
//
// Gets a list of supported Oracle Grid Infrastructure minor versions for the given major version and shape family.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := database.GetGiVersionMinorVersions(ctx, &database.GetGiVersionMinorVersionsArgs{
//				Version:                    giVersionMinorVersionVersion,
//				AvailabilityDomain:         pulumi.StringRef(giVersionMinorVersionAvailabilityDomain),
//				CompartmentId:              pulumi.StringRef(compartmentId),
//				IsGiVersionForProvisioning: pulumi.BoolRef(giVersionMinorVersionIsGiVersionForProvisioning),
//				Shape:                      pulumi.StringRef(giVersionMinorVersionShape),
//				ShapeFamily:                pulumi.StringRef(giVersionMinorVersionShapeFamily),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetGiVersionMinorVersions(ctx *pulumi.Context, args *GetGiVersionMinorVersionsArgs, opts ...pulumi.InvokeOption) (*GetGiVersionMinorVersionsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetGiVersionMinorVersionsResult
	err := ctx.Invoke("oci:Database/getGiVersionMinorVersions:getGiVersionMinorVersions", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getGiVersionMinorVersions.
type GetGiVersionMinorVersionsArgs struct {
	// The target availability domain. Only passed if the limit is AD-specific.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId *string                           `pulumi:"compartmentId"`
	Filters       []GetGiVersionMinorVersionsFilter `pulumi:"filters"`
	// If true, returns the Grid Infrastructure versions that can be used for provisioning a cluster
	IsGiVersionForProvisioning *bool `pulumi:"isGiVersionForProvisioning"`
	// If provided, filters the results for the given shape.
	Shape *string `pulumi:"shape"`
	// If provided, filters the results to the set of database versions which are supported for the given shape family.
	ShapeFamily *string `pulumi:"shapeFamily"`
	// The Oracle Grid Infrastructure major version.
	Version string `pulumi:"version"`
}

// A collection of values returned by getGiVersionMinorVersions.
type GetGiVersionMinorVersionsResult struct {
	AvailabilityDomain *string                           `pulumi:"availabilityDomain"`
	CompartmentId      *string                           `pulumi:"compartmentId"`
	Filters            []GetGiVersionMinorVersionsFilter `pulumi:"filters"`
	// The list of gi_minor_versions.
	GiMinorVersions []GetGiVersionMinorVersionsGiMinorVersion `pulumi:"giMinorVersions"`
	// The provider-assigned unique ID for this managed resource.
	Id                         string  `pulumi:"id"`
	IsGiVersionForProvisioning *bool   `pulumi:"isGiVersionForProvisioning"`
	Shape                      *string `pulumi:"shape"`
	ShapeFamily                *string `pulumi:"shapeFamily"`
	// A valid Oracle Grid Infrastructure (GI) software version.
	Version string `pulumi:"version"`
}

func GetGiVersionMinorVersionsOutput(ctx *pulumi.Context, args GetGiVersionMinorVersionsOutputArgs, opts ...pulumi.InvokeOption) GetGiVersionMinorVersionsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetGiVersionMinorVersionsResultOutput, error) {
			args := v.(GetGiVersionMinorVersionsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getGiVersionMinorVersions:getGiVersionMinorVersions", args, GetGiVersionMinorVersionsResultOutput{}, options).(GetGiVersionMinorVersionsResultOutput), nil
		}).(GetGiVersionMinorVersionsResultOutput)
}

// A collection of arguments for invoking getGiVersionMinorVersions.
type GetGiVersionMinorVersionsOutputArgs struct {
	// The target availability domain. Only passed if the limit is AD-specific.
	AvailabilityDomain pulumi.StringPtrInput `pulumi:"availabilityDomain"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringPtrInput                     `pulumi:"compartmentId"`
	Filters       GetGiVersionMinorVersionsFilterArrayInput `pulumi:"filters"`
	// If true, returns the Grid Infrastructure versions that can be used for provisioning a cluster
	IsGiVersionForProvisioning pulumi.BoolPtrInput `pulumi:"isGiVersionForProvisioning"`
	// If provided, filters the results for the given shape.
	Shape pulumi.StringPtrInput `pulumi:"shape"`
	// If provided, filters the results to the set of database versions which are supported for the given shape family.
	ShapeFamily pulumi.StringPtrInput `pulumi:"shapeFamily"`
	// The Oracle Grid Infrastructure major version.
	Version pulumi.StringInput `pulumi:"version"`
}

func (GetGiVersionMinorVersionsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetGiVersionMinorVersionsArgs)(nil)).Elem()
}

// A collection of values returned by getGiVersionMinorVersions.
type GetGiVersionMinorVersionsResultOutput struct{ *pulumi.OutputState }

func (GetGiVersionMinorVersionsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetGiVersionMinorVersionsResult)(nil)).Elem()
}

func (o GetGiVersionMinorVersionsResultOutput) ToGetGiVersionMinorVersionsResultOutput() GetGiVersionMinorVersionsResultOutput {
	return o
}

func (o GetGiVersionMinorVersionsResultOutput) ToGetGiVersionMinorVersionsResultOutputWithContext(ctx context.Context) GetGiVersionMinorVersionsResultOutput {
	return o
}

func (o GetGiVersionMinorVersionsResultOutput) AvailabilityDomain() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetGiVersionMinorVersionsResult) *string { return v.AvailabilityDomain }).(pulumi.StringPtrOutput)
}

func (o GetGiVersionMinorVersionsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetGiVersionMinorVersionsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

func (o GetGiVersionMinorVersionsResultOutput) Filters() GetGiVersionMinorVersionsFilterArrayOutput {
	return o.ApplyT(func(v GetGiVersionMinorVersionsResult) []GetGiVersionMinorVersionsFilter { return v.Filters }).(GetGiVersionMinorVersionsFilterArrayOutput)
}

// The list of gi_minor_versions.
func (o GetGiVersionMinorVersionsResultOutput) GiMinorVersions() GetGiVersionMinorVersionsGiMinorVersionArrayOutput {
	return o.ApplyT(func(v GetGiVersionMinorVersionsResult) []GetGiVersionMinorVersionsGiMinorVersion {
		return v.GiMinorVersions
	}).(GetGiVersionMinorVersionsGiMinorVersionArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetGiVersionMinorVersionsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetGiVersionMinorVersionsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetGiVersionMinorVersionsResultOutput) IsGiVersionForProvisioning() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetGiVersionMinorVersionsResult) *bool { return v.IsGiVersionForProvisioning }).(pulumi.BoolPtrOutput)
}

func (o GetGiVersionMinorVersionsResultOutput) Shape() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetGiVersionMinorVersionsResult) *string { return v.Shape }).(pulumi.StringPtrOutput)
}

func (o GetGiVersionMinorVersionsResultOutput) ShapeFamily() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetGiVersionMinorVersionsResult) *string { return v.ShapeFamily }).(pulumi.StringPtrOutput)
}

// A valid Oracle Grid Infrastructure (GI) software version.
func (o GetGiVersionMinorVersionsResultOutput) Version() pulumi.StringOutput {
	return o.ApplyT(func(v GetGiVersionMinorVersionsResult) string { return v.Version }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetGiVersionMinorVersionsResultOutput{})
}
