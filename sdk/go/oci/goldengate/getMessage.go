// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package goldengate

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Message resource in Oracle Cloud Infrastructure Golden Gate service.
//
// Lists the DeploymentMessages for a deployment. The sorting order is not important. By default first will be Upgrade message, next Exception message and then Storage Utilization message.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/goldengate"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := goldengate.GetMessage(ctx, &goldengate.GetMessageArgs{
//				DeploymentId: testDeployment.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetMessage(ctx *pulumi.Context, args *GetMessageArgs, opts ...pulumi.InvokeOption) (*GetMessageResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetMessageResult
	err := ctx.Invoke("oci:GoldenGate/getMessage:getMessage", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMessage.
type GetMessageArgs struct {
	// A unique Deployment identifier.
	DeploymentId string `pulumi:"deploymentId"`
}

// A collection of values returned by getMessage.
type GetMessageResult struct {
	DeploymentId string `pulumi:"deploymentId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// An array of DeploymentMessages.
	Items []GetMessageItem `pulumi:"items"`
}

func GetMessageOutput(ctx *pulumi.Context, args GetMessageOutputArgs, opts ...pulumi.InvokeOption) GetMessageResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetMessageResultOutput, error) {
			args := v.(GetMessageArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:GoldenGate/getMessage:getMessage", args, GetMessageResultOutput{}, options).(GetMessageResultOutput), nil
		}).(GetMessageResultOutput)
}

// A collection of arguments for invoking getMessage.
type GetMessageOutputArgs struct {
	// A unique Deployment identifier.
	DeploymentId pulumi.StringInput `pulumi:"deploymentId"`
}

func (GetMessageOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMessageArgs)(nil)).Elem()
}

// A collection of values returned by getMessage.
type GetMessageResultOutput struct{ *pulumi.OutputState }

func (GetMessageResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMessageResult)(nil)).Elem()
}

func (o GetMessageResultOutput) ToGetMessageResultOutput() GetMessageResultOutput {
	return o
}

func (o GetMessageResultOutput) ToGetMessageResultOutputWithContext(ctx context.Context) GetMessageResultOutput {
	return o
}

func (o GetMessageResultOutput) DeploymentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetMessageResult) string { return v.DeploymentId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetMessageResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetMessageResult) string { return v.Id }).(pulumi.StringOutput)
}

// An array of DeploymentMessages.
func (o GetMessageResultOutput) Items() GetMessageItemArrayOutput {
	return o.ApplyT(func(v GetMessageResult) []GetMessageItem { return v.Items }).(GetMessageItemArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetMessageResultOutput{})
}
