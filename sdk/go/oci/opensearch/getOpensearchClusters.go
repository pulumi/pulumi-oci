// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package opensearch

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Opensearch Clusters in Oracle Cloud Infrastructure Opensearch service.
//
// Returns a list of OpensearchClusters.
//
// ## Prerequisites
//
// # The below policies must be created in compartment before creating OpensearchCluster
//
// ##### {Compartment-Name} - Name of  your compartment
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			return nil
//		})
//	}
//
// ```
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Opensearch"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Opensearch.GetOpensearchClusters(ctx, &opensearch.GetOpensearchClustersArgs{
//				CompartmentId: _var.Compartment_id,
//				DisplayName:   pulumi.StringRef(_var.Opensearch_cluster_display_name),
//				Id:            pulumi.StringRef(_var.Opensearch_cluster_id),
//				State:         pulumi.StringRef(_var.Opensearch_cluster_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetOpensearchClusters(ctx *pulumi.Context, args *GetOpensearchClustersArgs, opts ...pulumi.InvokeOption) (*GetOpensearchClustersResult, error) {
	var rv GetOpensearchClustersResult
	err := ctx.Invoke("oci:Opensearch/getOpensearchClusters:getOpensearchClusters", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getOpensearchClusters.
type GetOpensearchClustersArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                       `pulumi:"displayName"`
	Filters     []GetOpensearchClustersFilter `pulumi:"filters"`
	// unique OpensearchCluster identifier
	Id *string `pulumi:"id"`
	// A filter to return only OpensearchClusters their lifecycleState matches the given lifecycleState.
	State *string `pulumi:"state"`
}

// A collection of values returned by getOpensearchClusters.
type GetOpensearchClustersResult struct {
	// The OCID of the compartment where the cluster is located.
	CompartmentId string `pulumi:"compartmentId"`
	// The name of the cluster. Avoid entering confidential information.
	DisplayName *string                       `pulumi:"displayName"`
	Filters     []GetOpensearchClustersFilter `pulumi:"filters"`
	// The OCID of the cluster.
	Id *string `pulumi:"id"`
	// The list of opensearch_cluster_collection.
	OpensearchClusterCollections []GetOpensearchClustersOpensearchClusterCollection `pulumi:"opensearchClusterCollections"`
	// The current state of the cluster.
	State *string `pulumi:"state"`
}

func GetOpensearchClustersOutput(ctx *pulumi.Context, args GetOpensearchClustersOutputArgs, opts ...pulumi.InvokeOption) GetOpensearchClustersResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetOpensearchClustersResult, error) {
			args := v.(GetOpensearchClustersArgs)
			r, err := GetOpensearchClusters(ctx, &args, opts...)
			var s GetOpensearchClustersResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetOpensearchClustersResultOutput)
}

// A collection of arguments for invoking getOpensearchClusters.
type GetOpensearchClustersOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput                 `pulumi:"displayName"`
	Filters     GetOpensearchClustersFilterArrayInput `pulumi:"filters"`
	// unique OpensearchCluster identifier
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to return only OpensearchClusters their lifecycleState matches the given lifecycleState.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetOpensearchClustersOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOpensearchClustersArgs)(nil)).Elem()
}

// A collection of values returned by getOpensearchClusters.
type GetOpensearchClustersResultOutput struct{ *pulumi.OutputState }

func (GetOpensearchClustersResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOpensearchClustersResult)(nil)).Elem()
}

func (o GetOpensearchClustersResultOutput) ToGetOpensearchClustersResultOutput() GetOpensearchClustersResultOutput {
	return o
}

func (o GetOpensearchClustersResultOutput) ToGetOpensearchClustersResultOutputWithContext(ctx context.Context) GetOpensearchClustersResultOutput {
	return o
}

// The OCID of the compartment where the cluster is located.
func (o GetOpensearchClustersResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetOpensearchClustersResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The name of the cluster. Avoid entering confidential information.
func (o GetOpensearchClustersResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOpensearchClustersResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetOpensearchClustersResultOutput) Filters() GetOpensearchClustersFilterArrayOutput {
	return o.ApplyT(func(v GetOpensearchClustersResult) []GetOpensearchClustersFilter { return v.Filters }).(GetOpensearchClustersFilterArrayOutput)
}

// The OCID of the cluster.
func (o GetOpensearchClustersResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOpensearchClustersResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The list of opensearch_cluster_collection.
func (o GetOpensearchClustersResultOutput) OpensearchClusterCollections() GetOpensearchClustersOpensearchClusterCollectionArrayOutput {
	return o.ApplyT(func(v GetOpensearchClustersResult) []GetOpensearchClustersOpensearchClusterCollection {
		return v.OpensearchClusterCollections
	}).(GetOpensearchClustersOpensearchClusterCollectionArrayOutput)
}

// The current state of the cluster.
func (o GetOpensearchClustersResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOpensearchClustersResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetOpensearchClustersResultOutput{})
}