// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package containerengine

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Cluster Kube Config resource in Oracle Cloud Infrastructure Container Engine service.
//
// Create the Kubeconfig YAML for a cluster.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/ContainerEngine"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := ContainerEngine.GetClusterKubeConfig(ctx, &containerengine.GetClusterKubeConfigArgs{
//				ClusterId:    oci_containerengine_cluster.Test_cluster.Id,
//				Endpoint:     pulumi.StringRef(_var.Cluster_kube_config_endpoint),
//				Expiration:   pulumi.IntRef(_var.Cluster_kube_config_expiration),
//				TokenVersion: pulumi.StringRef(_var.Cluster_kube_config_token_version),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetClusterKubeConfig(ctx *pulumi.Context, args *GetClusterKubeConfigArgs, opts ...pulumi.InvokeOption) (*GetClusterKubeConfigResult, error) {
	var rv GetClusterKubeConfigResult
	err := ctx.Invoke("oci:ContainerEngine/getClusterKubeConfig:getClusterKubeConfig", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getClusterKubeConfig.
type GetClusterKubeConfigArgs struct {
	// The OCID of the cluster.
	ClusterId string `pulumi:"clusterId"`
	// The endpoint to target. A cluster may have multiple endpoints exposed but the kubeconfig can only target one at a time.
	Endpoint *string `pulumi:"endpoint"`
	// Deprecated. This field is no longer used.
	Expiration *int `pulumi:"expiration"`
	// The version of the kubeconfig token. Supported value 2.0.0
	TokenVersion *string `pulumi:"tokenVersion"`
}

// A collection of values returned by getClusterKubeConfig.
type GetClusterKubeConfigResult struct {
	ClusterId string `pulumi:"clusterId"`
	// content of the Kubeconfig YAML for the cluster.
	Content    string  `pulumi:"content"`
	Endpoint   *string `pulumi:"endpoint"`
	Expiration *int    `pulumi:"expiration"`
	// The provider-assigned unique ID for this managed resource.
	Id           string  `pulumi:"id"`
	TokenVersion *string `pulumi:"tokenVersion"`
}

func GetClusterKubeConfigOutput(ctx *pulumi.Context, args GetClusterKubeConfigOutputArgs, opts ...pulumi.InvokeOption) GetClusterKubeConfigResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetClusterKubeConfigResult, error) {
			args := v.(GetClusterKubeConfigArgs)
			r, err := GetClusterKubeConfig(ctx, &args, opts...)
			var s GetClusterKubeConfigResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetClusterKubeConfigResultOutput)
}

// A collection of arguments for invoking getClusterKubeConfig.
type GetClusterKubeConfigOutputArgs struct {
	// The OCID of the cluster.
	ClusterId pulumi.StringInput `pulumi:"clusterId"`
	// The endpoint to target. A cluster may have multiple endpoints exposed but the kubeconfig can only target one at a time.
	Endpoint pulumi.StringPtrInput `pulumi:"endpoint"`
	// Deprecated. This field is no longer used.
	Expiration pulumi.IntPtrInput `pulumi:"expiration"`
	// The version of the kubeconfig token. Supported value 2.0.0
	TokenVersion pulumi.StringPtrInput `pulumi:"tokenVersion"`
}

func (GetClusterKubeConfigOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetClusterKubeConfigArgs)(nil)).Elem()
}

// A collection of values returned by getClusterKubeConfig.
type GetClusterKubeConfigResultOutput struct{ *pulumi.OutputState }

func (GetClusterKubeConfigResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetClusterKubeConfigResult)(nil)).Elem()
}

func (o GetClusterKubeConfigResultOutput) ToGetClusterKubeConfigResultOutput() GetClusterKubeConfigResultOutput {
	return o
}

func (o GetClusterKubeConfigResultOutput) ToGetClusterKubeConfigResultOutputWithContext(ctx context.Context) GetClusterKubeConfigResultOutput {
	return o
}

func (o GetClusterKubeConfigResultOutput) ClusterId() pulumi.StringOutput {
	return o.ApplyT(func(v GetClusterKubeConfigResult) string { return v.ClusterId }).(pulumi.StringOutput)
}

// content of the Kubeconfig YAML for the cluster.
func (o GetClusterKubeConfigResultOutput) Content() pulumi.StringOutput {
	return o.ApplyT(func(v GetClusterKubeConfigResult) string { return v.Content }).(pulumi.StringOutput)
}

func (o GetClusterKubeConfigResultOutput) Endpoint() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetClusterKubeConfigResult) *string { return v.Endpoint }).(pulumi.StringPtrOutput)
}

func (o GetClusterKubeConfigResultOutput) Expiration() pulumi.IntPtrOutput {
	return o.ApplyT(func(v GetClusterKubeConfigResult) *int { return v.Expiration }).(pulumi.IntPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetClusterKubeConfigResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetClusterKubeConfigResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetClusterKubeConfigResultOutput) TokenVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetClusterKubeConfigResult) *string { return v.TokenVersion }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetClusterKubeConfigResultOutput{})
}