// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package generativeai

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Models in Oracle Cloud Infrastructure Generative AI service.
//
// Lists the models in a specific compartment. Includes pretrained base models and fine-tuned custom models.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/generativeai"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := generativeai.GetModels(ctx, &generativeai.GetModelsArgs{
//				CompartmentId: compartmentId,
//				Capabilities:  modelCapability,
//				DisplayName:   pulumi.StringRef(modelDisplayName),
//				Id:            pulumi.StringRef(modelId),
//				State:         pulumi.StringRef(modelState),
//				Vendor:        pulumi.StringRef(modelVendor),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetModels(ctx *pulumi.Context, args *GetModelsArgs, opts ...pulumi.InvokeOption) (*GetModelsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetModelsResult
	err := ctx.Invoke("oci:GenerativeAi/getModels:getModels", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getModels.
type GetModelsArgs struct {
	// A filter to return only resources their capability matches the given capability.
	Capabilities []string `pulumi:"capabilities"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string           `pulumi:"displayName"`
	Filters     []GetModelsFilter `pulumi:"filters"`
	// The ID of the model.
	Id *string `pulumi:"id"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State *string `pulumi:"state"`
	// A filter to return only resources that match the entire vendor given.
	Vendor *string `pulumi:"vendor"`
}

// A collection of values returned by getModels.
type GetModelsResult struct {
	Capabilities []string `pulumi:"capabilities"`
	// The compartment OCID for fine-tuned models. For pretrained models, this value is null.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name.
	DisplayName *string           `pulumi:"displayName"`
	Filters     []GetModelsFilter `pulumi:"filters"`
	// An ID that uniquely identifies a pretrained or fine-tuned model.
	Id *string `pulumi:"id"`
	// The list of model_collection.
	ModelCollections []GetModelsModelCollection `pulumi:"modelCollections"`
	// The lifecycle state of the model.
	State *string `pulumi:"state"`
	// The provider of the base model.
	Vendor *string `pulumi:"vendor"`
}

func GetModelsOutput(ctx *pulumi.Context, args GetModelsOutputArgs, opts ...pulumi.InvokeOption) GetModelsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetModelsResultOutput, error) {
			args := v.(GetModelsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:GenerativeAi/getModels:getModels", args, GetModelsResultOutput{}, options).(GetModelsResultOutput), nil
		}).(GetModelsResultOutput)
}

// A collection of arguments for invoking getModels.
type GetModelsOutputArgs struct {
	// A filter to return only resources their capability matches the given capability.
	Capabilities pulumi.StringArrayInput `pulumi:"capabilities"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput     `pulumi:"displayName"`
	Filters     GetModelsFilterArrayInput `pulumi:"filters"`
	// The ID of the model.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State pulumi.StringPtrInput `pulumi:"state"`
	// A filter to return only resources that match the entire vendor given.
	Vendor pulumi.StringPtrInput `pulumi:"vendor"`
}

func (GetModelsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetModelsArgs)(nil)).Elem()
}

// A collection of values returned by getModels.
type GetModelsResultOutput struct{ *pulumi.OutputState }

func (GetModelsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetModelsResult)(nil)).Elem()
}

func (o GetModelsResultOutput) ToGetModelsResultOutput() GetModelsResultOutput {
	return o
}

func (o GetModelsResultOutput) ToGetModelsResultOutputWithContext(ctx context.Context) GetModelsResultOutput {
	return o
}

func (o GetModelsResultOutput) Capabilities() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetModelsResult) []string { return v.Capabilities }).(pulumi.StringArrayOutput)
}

// The compartment OCID for fine-tuned models. For pretrained models, this value is null.
func (o GetModelsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetModelsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name.
func (o GetModelsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetModelsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetModelsResultOutput) Filters() GetModelsFilterArrayOutput {
	return o.ApplyT(func(v GetModelsResult) []GetModelsFilter { return v.Filters }).(GetModelsFilterArrayOutput)
}

// An ID that uniquely identifies a pretrained or fine-tuned model.
func (o GetModelsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetModelsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The list of model_collection.
func (o GetModelsResultOutput) ModelCollections() GetModelsModelCollectionArrayOutput {
	return o.ApplyT(func(v GetModelsResult) []GetModelsModelCollection { return v.ModelCollections }).(GetModelsModelCollectionArrayOutput)
}

// The lifecycle state of the model.
func (o GetModelsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetModelsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The provider of the base model.
func (o GetModelsResultOutput) Vendor() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetModelsResult) *string { return v.Vendor }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetModelsResultOutput{})
}
