// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Cloud Exadata Infrastructures in Oracle Cloud Infrastructure Database service.
//
// Gets a list of the cloud Exadata infrastructure resources in the specified compartment. Applies to Exadata Cloud Service instances and Autonomous Database on dedicated Exadata infrastructure only.
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
//			_, err := database.GetCloudExadataInfrastructures(ctx, &database.GetCloudExadataInfrastructuresArgs{
//				CompartmentId:           compartmentId,
//				ClusterPlacementGroupId: pulumi.StringRef(cloudExadataInfrastructureClusterPlacementGroupId),
//				DisplayName:             pulumi.StringRef(cloudExadataInfrastructureDisplayName),
//				State:                   pulumi.StringRef(cloudExadataInfrastructureState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetCloudExadataInfrastructures(ctx *pulumi.Context, args *GetCloudExadataInfrastructuresArgs, opts ...pulumi.InvokeOption) (*GetCloudExadataInfrastructuresResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetCloudExadataInfrastructuresResult
	err := ctx.Invoke("oci:Database/getCloudExadataInfrastructures:getCloudExadataInfrastructures", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCloudExadataInfrastructures.
type GetCloudExadataInfrastructuresArgs struct {
	// A filter to return only resources that match the given cluster placement group ID exactly.
	ClusterPlacementGroupId *string `pulumi:"clusterPlacementGroupId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName *string                                `pulumi:"displayName"`
	Filters     []GetCloudExadataInfrastructuresFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
}

// A collection of values returned by getCloudExadataInfrastructures.
type GetCloudExadataInfrastructuresResult struct {
	// The list of cloud_exadata_infrastructures.
	CloudExadataInfrastructures []GetCloudExadataInfrastructuresCloudExadataInfrastructure `pulumi:"cloudExadataInfrastructures"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group of the Exadata Infrastructure.
	ClusterPlacementGroupId *string `pulumi:"clusterPlacementGroupId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The user-friendly name for the cloud Exadata infrastructure resource. The name does not need to be unique.
	DisplayName *string                                `pulumi:"displayName"`
	Filters     []GetCloudExadataInfrastructuresFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current lifecycle state of the cloud Exadata infrastructure resource.
	State *string `pulumi:"state"`
}

func GetCloudExadataInfrastructuresOutput(ctx *pulumi.Context, args GetCloudExadataInfrastructuresOutputArgs, opts ...pulumi.InvokeOption) GetCloudExadataInfrastructuresResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetCloudExadataInfrastructuresResultOutput, error) {
			args := v.(GetCloudExadataInfrastructuresArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getCloudExadataInfrastructures:getCloudExadataInfrastructures", args, GetCloudExadataInfrastructuresResultOutput{}, options).(GetCloudExadataInfrastructuresResultOutput), nil
		}).(GetCloudExadataInfrastructuresResultOutput)
}

// A collection of arguments for invoking getCloudExadataInfrastructures.
type GetCloudExadataInfrastructuresOutputArgs struct {
	// A filter to return only resources that match the given cluster placement group ID exactly.
	ClusterPlacementGroupId pulumi.StringPtrInput `pulumi:"clusterPlacementGroupId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName pulumi.StringPtrInput                          `pulumi:"displayName"`
	Filters     GetCloudExadataInfrastructuresFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetCloudExadataInfrastructuresOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCloudExadataInfrastructuresArgs)(nil)).Elem()
}

// A collection of values returned by getCloudExadataInfrastructures.
type GetCloudExadataInfrastructuresResultOutput struct{ *pulumi.OutputState }

func (GetCloudExadataInfrastructuresResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCloudExadataInfrastructuresResult)(nil)).Elem()
}

func (o GetCloudExadataInfrastructuresResultOutput) ToGetCloudExadataInfrastructuresResultOutput() GetCloudExadataInfrastructuresResultOutput {
	return o
}

func (o GetCloudExadataInfrastructuresResultOutput) ToGetCloudExadataInfrastructuresResultOutputWithContext(ctx context.Context) GetCloudExadataInfrastructuresResultOutput {
	return o
}

// The list of cloud_exadata_infrastructures.
func (o GetCloudExadataInfrastructuresResultOutput) CloudExadataInfrastructures() GetCloudExadataInfrastructuresCloudExadataInfrastructureArrayOutput {
	return o.ApplyT(func(v GetCloudExadataInfrastructuresResult) []GetCloudExadataInfrastructuresCloudExadataInfrastructure {
		return v.CloudExadataInfrastructures
	}).(GetCloudExadataInfrastructuresCloudExadataInfrastructureArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group of the Exadata Infrastructure.
func (o GetCloudExadataInfrastructuresResultOutput) ClusterPlacementGroupId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCloudExadataInfrastructuresResult) *string { return v.ClusterPlacementGroupId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o GetCloudExadataInfrastructuresResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetCloudExadataInfrastructuresResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The user-friendly name for the cloud Exadata infrastructure resource. The name does not need to be unique.
func (o GetCloudExadataInfrastructuresResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCloudExadataInfrastructuresResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetCloudExadataInfrastructuresResultOutput) Filters() GetCloudExadataInfrastructuresFilterArrayOutput {
	return o.ApplyT(func(v GetCloudExadataInfrastructuresResult) []GetCloudExadataInfrastructuresFilter { return v.Filters }).(GetCloudExadataInfrastructuresFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetCloudExadataInfrastructuresResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetCloudExadataInfrastructuresResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current lifecycle state of the cloud Exadata infrastructure resource.
func (o GetCloudExadataInfrastructuresResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCloudExadataInfrastructuresResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetCloudExadataInfrastructuresResultOutput{})
}
