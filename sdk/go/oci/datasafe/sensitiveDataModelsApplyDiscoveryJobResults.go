// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type SensitiveDataModelsApplyDiscoveryJobResults struct {
	pulumi.CustomResourceState

	DiscoveryJobId       pulumi.StringOutput `pulumi:"discoveryJobId"`
	SensitiveDataModelId pulumi.StringOutput `pulumi:"sensitiveDataModelId"`
}

// NewSensitiveDataModelsApplyDiscoveryJobResults registers a new resource with the given unique name, arguments, and options.
func NewSensitiveDataModelsApplyDiscoveryJobResults(ctx *pulumi.Context,
	name string, args *SensitiveDataModelsApplyDiscoveryJobResultsArgs, opts ...pulumi.ResourceOption) (*SensitiveDataModelsApplyDiscoveryJobResults, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.DiscoveryJobId == nil {
		return nil, errors.New("invalid value for required argument 'DiscoveryJobId'")
	}
	if args.SensitiveDataModelId == nil {
		return nil, errors.New("invalid value for required argument 'SensitiveDataModelId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource SensitiveDataModelsApplyDiscoveryJobResults
	err := ctx.RegisterResource("oci:DataSafe/sensitiveDataModelsApplyDiscoveryJobResults:SensitiveDataModelsApplyDiscoveryJobResults", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetSensitiveDataModelsApplyDiscoveryJobResults gets an existing SensitiveDataModelsApplyDiscoveryJobResults resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetSensitiveDataModelsApplyDiscoveryJobResults(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *SensitiveDataModelsApplyDiscoveryJobResultsState, opts ...pulumi.ResourceOption) (*SensitiveDataModelsApplyDiscoveryJobResults, error) {
	var resource SensitiveDataModelsApplyDiscoveryJobResults
	err := ctx.ReadResource("oci:DataSafe/sensitiveDataModelsApplyDiscoveryJobResults:SensitiveDataModelsApplyDiscoveryJobResults", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering SensitiveDataModelsApplyDiscoveryJobResults resources.
type sensitiveDataModelsApplyDiscoveryJobResultsState struct {
	DiscoveryJobId       *string `pulumi:"discoveryJobId"`
	SensitiveDataModelId *string `pulumi:"sensitiveDataModelId"`
}

type SensitiveDataModelsApplyDiscoveryJobResultsState struct {
	DiscoveryJobId       pulumi.StringPtrInput
	SensitiveDataModelId pulumi.StringPtrInput
}

func (SensitiveDataModelsApplyDiscoveryJobResultsState) ElementType() reflect.Type {
	return reflect.TypeOf((*sensitiveDataModelsApplyDiscoveryJobResultsState)(nil)).Elem()
}

type sensitiveDataModelsApplyDiscoveryJobResultsArgs struct {
	DiscoveryJobId       string `pulumi:"discoveryJobId"`
	SensitiveDataModelId string `pulumi:"sensitiveDataModelId"`
}

// The set of arguments for constructing a SensitiveDataModelsApplyDiscoveryJobResults resource.
type SensitiveDataModelsApplyDiscoveryJobResultsArgs struct {
	DiscoveryJobId       pulumi.StringInput
	SensitiveDataModelId pulumi.StringInput
}

func (SensitiveDataModelsApplyDiscoveryJobResultsArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*sensitiveDataModelsApplyDiscoveryJobResultsArgs)(nil)).Elem()
}

type SensitiveDataModelsApplyDiscoveryJobResultsInput interface {
	pulumi.Input

	ToSensitiveDataModelsApplyDiscoveryJobResultsOutput() SensitiveDataModelsApplyDiscoveryJobResultsOutput
	ToSensitiveDataModelsApplyDiscoveryJobResultsOutputWithContext(ctx context.Context) SensitiveDataModelsApplyDiscoveryJobResultsOutput
}

func (*SensitiveDataModelsApplyDiscoveryJobResults) ElementType() reflect.Type {
	return reflect.TypeOf((**SensitiveDataModelsApplyDiscoveryJobResults)(nil)).Elem()
}

func (i *SensitiveDataModelsApplyDiscoveryJobResults) ToSensitiveDataModelsApplyDiscoveryJobResultsOutput() SensitiveDataModelsApplyDiscoveryJobResultsOutput {
	return i.ToSensitiveDataModelsApplyDiscoveryJobResultsOutputWithContext(context.Background())
}

func (i *SensitiveDataModelsApplyDiscoveryJobResults) ToSensitiveDataModelsApplyDiscoveryJobResultsOutputWithContext(ctx context.Context) SensitiveDataModelsApplyDiscoveryJobResultsOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SensitiveDataModelsApplyDiscoveryJobResultsOutput)
}

// SensitiveDataModelsApplyDiscoveryJobResultsArrayInput is an input type that accepts SensitiveDataModelsApplyDiscoveryJobResultsArray and SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput values.
// You can construct a concrete instance of `SensitiveDataModelsApplyDiscoveryJobResultsArrayInput` via:
//
//	SensitiveDataModelsApplyDiscoveryJobResultsArray{ SensitiveDataModelsApplyDiscoveryJobResultsArgs{...} }
type SensitiveDataModelsApplyDiscoveryJobResultsArrayInput interface {
	pulumi.Input

	ToSensitiveDataModelsApplyDiscoveryJobResultsArrayOutput() SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput
	ToSensitiveDataModelsApplyDiscoveryJobResultsArrayOutputWithContext(context.Context) SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput
}

type SensitiveDataModelsApplyDiscoveryJobResultsArray []SensitiveDataModelsApplyDiscoveryJobResultsInput

func (SensitiveDataModelsApplyDiscoveryJobResultsArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SensitiveDataModelsApplyDiscoveryJobResults)(nil)).Elem()
}

func (i SensitiveDataModelsApplyDiscoveryJobResultsArray) ToSensitiveDataModelsApplyDiscoveryJobResultsArrayOutput() SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput {
	return i.ToSensitiveDataModelsApplyDiscoveryJobResultsArrayOutputWithContext(context.Background())
}

func (i SensitiveDataModelsApplyDiscoveryJobResultsArray) ToSensitiveDataModelsApplyDiscoveryJobResultsArrayOutputWithContext(ctx context.Context) SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput)
}

// SensitiveDataModelsApplyDiscoveryJobResultsMapInput is an input type that accepts SensitiveDataModelsApplyDiscoveryJobResultsMap and SensitiveDataModelsApplyDiscoveryJobResultsMapOutput values.
// You can construct a concrete instance of `SensitiveDataModelsApplyDiscoveryJobResultsMapInput` via:
//
//	SensitiveDataModelsApplyDiscoveryJobResultsMap{ "key": SensitiveDataModelsApplyDiscoveryJobResultsArgs{...} }
type SensitiveDataModelsApplyDiscoveryJobResultsMapInput interface {
	pulumi.Input

	ToSensitiveDataModelsApplyDiscoveryJobResultsMapOutput() SensitiveDataModelsApplyDiscoveryJobResultsMapOutput
	ToSensitiveDataModelsApplyDiscoveryJobResultsMapOutputWithContext(context.Context) SensitiveDataModelsApplyDiscoveryJobResultsMapOutput
}

type SensitiveDataModelsApplyDiscoveryJobResultsMap map[string]SensitiveDataModelsApplyDiscoveryJobResultsInput

func (SensitiveDataModelsApplyDiscoveryJobResultsMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SensitiveDataModelsApplyDiscoveryJobResults)(nil)).Elem()
}

func (i SensitiveDataModelsApplyDiscoveryJobResultsMap) ToSensitiveDataModelsApplyDiscoveryJobResultsMapOutput() SensitiveDataModelsApplyDiscoveryJobResultsMapOutput {
	return i.ToSensitiveDataModelsApplyDiscoveryJobResultsMapOutputWithContext(context.Background())
}

func (i SensitiveDataModelsApplyDiscoveryJobResultsMap) ToSensitiveDataModelsApplyDiscoveryJobResultsMapOutputWithContext(ctx context.Context) SensitiveDataModelsApplyDiscoveryJobResultsMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SensitiveDataModelsApplyDiscoveryJobResultsMapOutput)
}

type SensitiveDataModelsApplyDiscoveryJobResultsOutput struct{ *pulumi.OutputState }

func (SensitiveDataModelsApplyDiscoveryJobResultsOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**SensitiveDataModelsApplyDiscoveryJobResults)(nil)).Elem()
}

func (o SensitiveDataModelsApplyDiscoveryJobResultsOutput) ToSensitiveDataModelsApplyDiscoveryJobResultsOutput() SensitiveDataModelsApplyDiscoveryJobResultsOutput {
	return o
}

func (o SensitiveDataModelsApplyDiscoveryJobResultsOutput) ToSensitiveDataModelsApplyDiscoveryJobResultsOutputWithContext(ctx context.Context) SensitiveDataModelsApplyDiscoveryJobResultsOutput {
	return o
}

func (o SensitiveDataModelsApplyDiscoveryJobResultsOutput) DiscoveryJobId() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveDataModelsApplyDiscoveryJobResults) pulumi.StringOutput { return v.DiscoveryJobId }).(pulumi.StringOutput)
}

func (o SensitiveDataModelsApplyDiscoveryJobResultsOutput) SensitiveDataModelId() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveDataModelsApplyDiscoveryJobResults) pulumi.StringOutput {
		return v.SensitiveDataModelId
	}).(pulumi.StringOutput)
}

type SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput struct{ *pulumi.OutputState }

func (SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SensitiveDataModelsApplyDiscoveryJobResults)(nil)).Elem()
}

func (o SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput) ToSensitiveDataModelsApplyDiscoveryJobResultsArrayOutput() SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput {
	return o
}

func (o SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput) ToSensitiveDataModelsApplyDiscoveryJobResultsArrayOutputWithContext(ctx context.Context) SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput {
	return o
}

func (o SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput) Index(i pulumi.IntInput) SensitiveDataModelsApplyDiscoveryJobResultsOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *SensitiveDataModelsApplyDiscoveryJobResults {
		return vs[0].([]*SensitiveDataModelsApplyDiscoveryJobResults)[vs[1].(int)]
	}).(SensitiveDataModelsApplyDiscoveryJobResultsOutput)
}

type SensitiveDataModelsApplyDiscoveryJobResultsMapOutput struct{ *pulumi.OutputState }

func (SensitiveDataModelsApplyDiscoveryJobResultsMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SensitiveDataModelsApplyDiscoveryJobResults)(nil)).Elem()
}

func (o SensitiveDataModelsApplyDiscoveryJobResultsMapOutput) ToSensitiveDataModelsApplyDiscoveryJobResultsMapOutput() SensitiveDataModelsApplyDiscoveryJobResultsMapOutput {
	return o
}

func (o SensitiveDataModelsApplyDiscoveryJobResultsMapOutput) ToSensitiveDataModelsApplyDiscoveryJobResultsMapOutputWithContext(ctx context.Context) SensitiveDataModelsApplyDiscoveryJobResultsMapOutput {
	return o
}

func (o SensitiveDataModelsApplyDiscoveryJobResultsMapOutput) MapIndex(k pulumi.StringInput) SensitiveDataModelsApplyDiscoveryJobResultsOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *SensitiveDataModelsApplyDiscoveryJobResults {
		return vs[0].(map[string]*SensitiveDataModelsApplyDiscoveryJobResults)[vs[1].(string)]
	}).(SensitiveDataModelsApplyDiscoveryJobResultsOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*SensitiveDataModelsApplyDiscoveryJobResultsInput)(nil)).Elem(), &SensitiveDataModelsApplyDiscoveryJobResults{})
	pulumi.RegisterInputType(reflect.TypeOf((*SensitiveDataModelsApplyDiscoveryJobResultsArrayInput)(nil)).Elem(), SensitiveDataModelsApplyDiscoveryJobResultsArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*SensitiveDataModelsApplyDiscoveryJobResultsMapInput)(nil)).Elem(), SensitiveDataModelsApplyDiscoveryJobResultsMap{})
	pulumi.RegisterOutputType(SensitiveDataModelsApplyDiscoveryJobResultsOutput{})
	pulumi.RegisterOutputType(SensitiveDataModelsApplyDiscoveryJobResultsArrayOutput{})
	pulumi.RegisterOutputType(SensitiveDataModelsApplyDiscoveryJobResultsMapOutput{})
}
