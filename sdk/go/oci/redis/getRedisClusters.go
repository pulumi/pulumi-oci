// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package redis

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides the list of Redis Clusters in Oracle Cloud Infrastructure Redis service.
//
// Lists the Redis clusters in the specified compartment. A Redis cluster is a memory-based storage solution. For more information, see [OCI Caching Service with Redis](https://docs.cloud.oracle.com/iaas/Content/redis/home.htm).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Redis"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Redis.GetRedisClusters(ctx, &redis.GetRedisClustersArgs{
//				CompartmentId: pulumi.StringRef(_var.Compartment_id),
//				DisplayName:   pulumi.StringRef(_var.Redis_cluster_display_name),
//				Id:            pulumi.StringRef(_var.Redis_cluster_id),
//				State:         pulumi.StringRef(_var.Redis_cluster_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetRedisClusters(ctx *pulumi.Context, args *GetRedisClustersArgs, opts ...pulumi.InvokeOption) (*GetRedisClustersResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetRedisClustersResult
	err := ctx.Invoke("oci:Redis/getRedisClusters:getRedisClusters", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRedisClusters.
type GetRedisClustersArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetRedisClustersFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the Redis cluster.
	Id *string `pulumi:"id"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State *string `pulumi:"state"`
}

// A collection of values returned by getRedisClusters.
type GetRedisClustersResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the compartment that contains the Redis cluster.
	CompartmentId *string `pulumi:"compartmentId"`
	// A user-friendly name of a Redis cluster node.
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetRedisClustersFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the Redis cluster.
	Id *string `pulumi:"id"`
	// The list of redis_cluster_collection.
	RedisClusterCollections []GetRedisClustersRedisClusterCollection `pulumi:"redisClusterCollections"`
	// The current state of the Redis cluster.
	State *string `pulumi:"state"`
}

func GetRedisClustersOutput(ctx *pulumi.Context, args GetRedisClustersOutputArgs, opts ...pulumi.InvokeOption) GetRedisClustersResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetRedisClustersResult, error) {
			args := v.(GetRedisClustersArgs)
			r, err := GetRedisClusters(ctx, &args, opts...)
			var s GetRedisClustersResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetRedisClustersResultOutput)
}

// A collection of arguments for invoking getRedisClusters.
type GetRedisClustersOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput            `pulumi:"displayName"`
	Filters     GetRedisClustersFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the Redis cluster.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetRedisClustersOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRedisClustersArgs)(nil)).Elem()
}

// A collection of values returned by getRedisClusters.
type GetRedisClustersResultOutput struct{ *pulumi.OutputState }

func (GetRedisClustersResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRedisClustersResult)(nil)).Elem()
}

func (o GetRedisClustersResultOutput) ToGetRedisClustersResultOutput() GetRedisClustersResultOutput {
	return o
}

func (o GetRedisClustersResultOutput) ToGetRedisClustersResultOutputWithContext(ctx context.Context) GetRedisClustersResultOutput {
	return o
}

func (o GetRedisClustersResultOutput) ToOutput(ctx context.Context) pulumix.Output[GetRedisClustersResult] {
	return pulumix.Output[GetRedisClustersResult]{
		OutputState: o.OutputState,
	}
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the compartment that contains the Redis cluster.
func (o GetRedisClustersResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRedisClustersResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// A user-friendly name of a Redis cluster node.
func (o GetRedisClustersResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRedisClustersResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetRedisClustersResultOutput) Filters() GetRedisClustersFilterArrayOutput {
	return o.ApplyT(func(v GetRedisClustersResult) []GetRedisClustersFilter { return v.Filters }).(GetRedisClustersFilterArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the Redis cluster.
func (o GetRedisClustersResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRedisClustersResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The list of redis_cluster_collection.
func (o GetRedisClustersResultOutput) RedisClusterCollections() GetRedisClustersRedisClusterCollectionArrayOutput {
	return o.ApplyT(func(v GetRedisClustersResult) []GetRedisClustersRedisClusterCollection {
		return v.RedisClusterCollections
	}).(GetRedisClustersRedisClusterCollectionArrayOutput)
}

// The current state of the Redis cluster.
func (o GetRedisClustersResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRedisClustersResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetRedisClustersResultOutput{})
}