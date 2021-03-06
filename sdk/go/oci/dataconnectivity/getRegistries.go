// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package dataconnectivity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Registries in Oracle Cloud Infrastructure Data Connectivity service.
//
// Returns a list of Data Connectivity Management Registries.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataConnectivity"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := DataConnectivity.GetRegistries(ctx, &dataconnectivity.GetRegistriesArgs{
// 			CompartmentId: _var.Compartment_id,
// 			IsDeepLookup:  pulumi.BoolRef(_var.Registry_is_deep_lookup),
// 			Name:          pulumi.StringRef(_var.Registry_name),
// 			State:         pulumi.StringRef(_var.Registry_state),
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetRegistries(ctx *pulumi.Context, args *GetRegistriesArgs, opts ...pulumi.InvokeOption) (*GetRegistriesResult, error) {
	var rv GetRegistriesResult
	err := ctx.Invoke("oci:DataConnectivity/getRegistries:getRegistries", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRegistries.
type GetRegistriesArgs struct {
	// The OCID of the compartment containing the resources you want to list.
	CompartmentId string                `pulumi:"compartmentId"`
	Filters       []GetRegistriesFilter `pulumi:"filters"`
	// This parameter allows list registries to deep look at whole tenancy.
	IsDeepLookup *bool `pulumi:"isDeepLookup"`
	// Used to filter by the name of the object.
	Name *string `pulumi:"name"`
	// Lifecycle state of the resource.
	State *string `pulumi:"state"`
}

// A collection of values returned by getRegistries.
type GetRegistriesResult struct {
	// Compartment Identifier
	CompartmentId string                `pulumi:"compartmentId"`
	Filters       []GetRegistriesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id           string  `pulumi:"id"`
	IsDeepLookup *bool   `pulumi:"isDeepLookup"`
	Name         *string `pulumi:"name"`
	// The list of registry_summary_collection.
	RegistrySummaryCollections []GetRegistriesRegistrySummaryCollection `pulumi:"registrySummaryCollections"`
	// Lifecycle states for registries in Data Connectivity Management Service CREATING - The resource is being created and may not be usable until the entire metadata is defined UPDATING - The resource is being updated and may not be usable until all changes are commited DELETING - The resource is being deleted and might require deep cleanup of children. ACTIVE   - The resource is valid and available for access INACTIVE - The resource might be incomplete in its definition or might have been made unavailable for administrative reasons DELETED  - The resource has been deleted and isn't available FAILED   - The resource is in a failed state due to validation or other errors
	State *string `pulumi:"state"`
}

func GetRegistriesOutput(ctx *pulumi.Context, args GetRegistriesOutputArgs, opts ...pulumi.InvokeOption) GetRegistriesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetRegistriesResult, error) {
			args := v.(GetRegistriesArgs)
			r, err := GetRegistries(ctx, &args, opts...)
			var s GetRegistriesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetRegistriesResultOutput)
}

// A collection of arguments for invoking getRegistries.
type GetRegistriesOutputArgs struct {
	// The OCID of the compartment containing the resources you want to list.
	CompartmentId pulumi.StringInput            `pulumi:"compartmentId"`
	Filters       GetRegistriesFilterArrayInput `pulumi:"filters"`
	// This parameter allows list registries to deep look at whole tenancy.
	IsDeepLookup pulumi.BoolPtrInput `pulumi:"isDeepLookup"`
	// Used to filter by the name of the object.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// Lifecycle state of the resource.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetRegistriesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRegistriesArgs)(nil)).Elem()
}

// A collection of values returned by getRegistries.
type GetRegistriesResultOutput struct{ *pulumi.OutputState }

func (GetRegistriesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRegistriesResult)(nil)).Elem()
}

func (o GetRegistriesResultOutput) ToGetRegistriesResultOutput() GetRegistriesResultOutput {
	return o
}

func (o GetRegistriesResultOutput) ToGetRegistriesResultOutputWithContext(ctx context.Context) GetRegistriesResultOutput {
	return o
}

// Compartment Identifier
func (o GetRegistriesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetRegistriesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetRegistriesResultOutput) Filters() GetRegistriesFilterArrayOutput {
	return o.ApplyT(func(v GetRegistriesResult) []GetRegistriesFilter { return v.Filters }).(GetRegistriesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetRegistriesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetRegistriesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetRegistriesResultOutput) IsDeepLookup() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetRegistriesResult) *bool { return v.IsDeepLookup }).(pulumi.BoolPtrOutput)
}

func (o GetRegistriesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRegistriesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The list of registry_summary_collection.
func (o GetRegistriesResultOutput) RegistrySummaryCollections() GetRegistriesRegistrySummaryCollectionArrayOutput {
	return o.ApplyT(func(v GetRegistriesResult) []GetRegistriesRegistrySummaryCollection {
		return v.RegistrySummaryCollections
	}).(GetRegistriesRegistrySummaryCollectionArrayOutput)
}

// Lifecycle states for registries in Data Connectivity Management Service CREATING - The resource is being created and may not be usable until the entire metadata is defined UPDATING - The resource is being updated and may not be usable until all changes are commited DELETING - The resource is being deleted and might require deep cleanup of children. ACTIVE   - The resource is valid and available for access INACTIVE - The resource might be incomplete in its definition or might have been made unavailable for administrative reasons DELETED  - The resource has been deleted and isn't available FAILED   - The resource is in a failed state due to validation or other errors
func (o GetRegistriesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRegistriesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetRegistriesResultOutput{})
}
