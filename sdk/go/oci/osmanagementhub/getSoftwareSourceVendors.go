// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package osmanagementhub

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides the list of Software Source Vendors in Oracle Cloud Infrastructure Os Management Hub service.
//
// Lists available software source vendors. Filter the list against a variety of criteria including but not limited
// to its name.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/OsManagementHub"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := OsManagementHub.GetSoftwareSourceVendors(ctx, &osmanagementhub.GetSoftwareSourceVendorsArgs{
//				CompartmentId: _var.Compartment_id,
//				Name:          pulumi.StringRef(_var.Software_source_vendor_name),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSoftwareSourceVendors(ctx *pulumi.Context, args *GetSoftwareSourceVendorsArgs, opts ...pulumi.InvokeOption) (*GetSoftwareSourceVendorsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetSoftwareSourceVendorsResult
	err := ctx.Invoke("oci:OsManagementHub/getSoftwareSourceVendors:getSoftwareSourceVendors", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSoftwareSourceVendors.
type GetSoftwareSourceVendorsArgs struct {
	// The OCID of the compartment that contains the resources to list. This parameter is required.
	CompartmentId string                           `pulumi:"compartmentId"`
	Filters       []GetSoftwareSourceVendorsFilter `pulumi:"filters"`
	// The name of the entity to be queried.
	Name *string `pulumi:"name"`
}

// A collection of values returned by getSoftwareSourceVendors.
type GetSoftwareSourceVendorsResult struct {
	CompartmentId string                           `pulumi:"compartmentId"`
	Filters       []GetSoftwareSourceVendorsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Name of the vendor providing the software source.
	Name *string `pulumi:"name"`
	// The list of software_source_vendor_collection.
	SoftwareSourceVendorCollections []GetSoftwareSourceVendorsSoftwareSourceVendorCollection `pulumi:"softwareSourceVendorCollections"`
}

func GetSoftwareSourceVendorsOutput(ctx *pulumi.Context, args GetSoftwareSourceVendorsOutputArgs, opts ...pulumi.InvokeOption) GetSoftwareSourceVendorsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetSoftwareSourceVendorsResult, error) {
			args := v.(GetSoftwareSourceVendorsArgs)
			r, err := GetSoftwareSourceVendors(ctx, &args, opts...)
			var s GetSoftwareSourceVendorsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetSoftwareSourceVendorsResultOutput)
}

// A collection of arguments for invoking getSoftwareSourceVendors.
type GetSoftwareSourceVendorsOutputArgs struct {
	// The OCID of the compartment that contains the resources to list. This parameter is required.
	CompartmentId pulumi.StringInput                       `pulumi:"compartmentId"`
	Filters       GetSoftwareSourceVendorsFilterArrayInput `pulumi:"filters"`
	// The name of the entity to be queried.
	Name pulumi.StringPtrInput `pulumi:"name"`
}

func (GetSoftwareSourceVendorsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSoftwareSourceVendorsArgs)(nil)).Elem()
}

// A collection of values returned by getSoftwareSourceVendors.
type GetSoftwareSourceVendorsResultOutput struct{ *pulumi.OutputState }

func (GetSoftwareSourceVendorsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSoftwareSourceVendorsResult)(nil)).Elem()
}

func (o GetSoftwareSourceVendorsResultOutput) ToGetSoftwareSourceVendorsResultOutput() GetSoftwareSourceVendorsResultOutput {
	return o
}

func (o GetSoftwareSourceVendorsResultOutput) ToGetSoftwareSourceVendorsResultOutputWithContext(ctx context.Context) GetSoftwareSourceVendorsResultOutput {
	return o
}

func (o GetSoftwareSourceVendorsResultOutput) ToOutput(ctx context.Context) pulumix.Output[GetSoftwareSourceVendorsResult] {
	return pulumix.Output[GetSoftwareSourceVendorsResult]{
		OutputState: o.OutputState,
	}
}

func (o GetSoftwareSourceVendorsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSoftwareSourceVendorsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetSoftwareSourceVendorsResultOutput) Filters() GetSoftwareSourceVendorsFilterArrayOutput {
	return o.ApplyT(func(v GetSoftwareSourceVendorsResult) []GetSoftwareSourceVendorsFilter { return v.Filters }).(GetSoftwareSourceVendorsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSoftwareSourceVendorsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSoftwareSourceVendorsResult) string { return v.Id }).(pulumi.StringOutput)
}

// Name of the vendor providing the software source.
func (o GetSoftwareSourceVendorsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSoftwareSourceVendorsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The list of software_source_vendor_collection.
func (o GetSoftwareSourceVendorsResultOutput) SoftwareSourceVendorCollections() GetSoftwareSourceVendorsSoftwareSourceVendorCollectionArrayOutput {
	return o.ApplyT(func(v GetSoftwareSourceVendorsResult) []GetSoftwareSourceVendorsSoftwareSourceVendorCollection {
		return v.SoftwareSourceVendorCollections
	}).(GetSoftwareSourceVendorsSoftwareSourceVendorCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSoftwareSourceVendorsResultOutput{})
}