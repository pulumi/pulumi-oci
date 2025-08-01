// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loganalytics

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Log Analytics Entity Type resource in Oracle Cloud Infrastructure Log Analytics service.
//
// Add custom log analytics entity type.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/loganalytics"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := loganalytics.NewLogAnalyticsEntityType(ctx, "test_log_analytics_entity_type", &loganalytics.LogAnalyticsEntityTypeArgs{
//				Name:      pulumi.Any(logAnalyticsEntityTypeName),
//				Namespace: pulumi.Any(logAnalyticsEntityTypeNamespace),
//				Category:  pulumi.Any(logAnalyticsEntityTypeCategory),
//				Properties: loganalytics.LogAnalyticsEntityTypePropertyArray{
//					&loganalytics.LogAnalyticsEntityTypePropertyArgs{
//						Name:        pulumi.Any(logAnalyticsEntityTypePropertiesName),
//						Description: pulumi.Any(logAnalyticsEntityTypePropertiesDescription),
//					},
//				},
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// LogAnalyticsEntityTypes can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:LogAnalytics/logAnalyticsEntityType:LogAnalyticsEntityType test_log_analytics_entity_type "namespaces/{namespaceName}/logAnalyticsEntityTypes"
// ```
type LogAnalyticsEntityType struct {
	pulumi.CustomResourceState

	// Log analytics entity type category. Category will be used for grouping and filtering.
	Category pulumi.StringOutput `pulumi:"category"`
	// Log analytics entity type group. This can be CLOUD (OCI) or NON_CLOUD otherwise.
	CloudType pulumi.StringOutput `pulumi:"cloudType"`
	// Internal name for the log analytics entity type.
	InternalName                     pulumi.StringOutput `pulumi:"internalName"`
	ManagementAgentEligibilityStatus pulumi.StringOutput `pulumi:"managementAgentEligibilityStatus"`
	// Log analytics entity type name.
	Name pulumi.StringOutput `pulumi:"name"`
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringOutput `pulumi:"namespace"`
	// Log analytics entity type property definition.
	Properties LogAnalyticsEntityTypePropertyArrayOutput `pulumi:"properties"`
	// The current lifecycle state of the log analytics entity type.
	State pulumi.StringOutput `pulumi:"state"`
	// Time the log analytics entity type was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// Time the log analytics entity type was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewLogAnalyticsEntityType registers a new resource with the given unique name, arguments, and options.
func NewLogAnalyticsEntityType(ctx *pulumi.Context,
	name string, args *LogAnalyticsEntityTypeArgs, opts ...pulumi.ResourceOption) (*LogAnalyticsEntityType, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Namespace == nil {
		return nil, errors.New("invalid value for required argument 'Namespace'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource LogAnalyticsEntityType
	err := ctx.RegisterResource("oci:LogAnalytics/logAnalyticsEntityType:LogAnalyticsEntityType", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLogAnalyticsEntityType gets an existing LogAnalyticsEntityType resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLogAnalyticsEntityType(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LogAnalyticsEntityTypeState, opts ...pulumi.ResourceOption) (*LogAnalyticsEntityType, error) {
	var resource LogAnalyticsEntityType
	err := ctx.ReadResource("oci:LogAnalytics/logAnalyticsEntityType:LogAnalyticsEntityType", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LogAnalyticsEntityType resources.
type logAnalyticsEntityTypeState struct {
	// Log analytics entity type category. Category will be used for grouping and filtering.
	Category *string `pulumi:"category"`
	// Log analytics entity type group. This can be CLOUD (OCI) or NON_CLOUD otherwise.
	CloudType *string `pulumi:"cloudType"`
	// Internal name for the log analytics entity type.
	InternalName                     *string `pulumi:"internalName"`
	ManagementAgentEligibilityStatus *string `pulumi:"managementAgentEligibilityStatus"`
	// Log analytics entity type name.
	Name *string `pulumi:"name"`
	// The Logging Analytics namespace used for the request.
	Namespace *string `pulumi:"namespace"`
	// Log analytics entity type property definition.
	Properties []LogAnalyticsEntityTypeProperty `pulumi:"properties"`
	// The current lifecycle state of the log analytics entity type.
	State *string `pulumi:"state"`
	// Time the log analytics entity type was created. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// Time the log analytics entity type was updated. An RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type LogAnalyticsEntityTypeState struct {
	// Log analytics entity type category. Category will be used for grouping and filtering.
	Category pulumi.StringPtrInput
	// Log analytics entity type group. This can be CLOUD (OCI) or NON_CLOUD otherwise.
	CloudType pulumi.StringPtrInput
	// Internal name for the log analytics entity type.
	InternalName                     pulumi.StringPtrInput
	ManagementAgentEligibilityStatus pulumi.StringPtrInput
	// Log analytics entity type name.
	Name pulumi.StringPtrInput
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringPtrInput
	// Log analytics entity type property definition.
	Properties LogAnalyticsEntityTypePropertyArrayInput
	// The current lifecycle state of the log analytics entity type.
	State pulumi.StringPtrInput
	// Time the log analytics entity type was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// Time the log analytics entity type was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (LogAnalyticsEntityTypeState) ElementType() reflect.Type {
	return reflect.TypeOf((*logAnalyticsEntityTypeState)(nil)).Elem()
}

type logAnalyticsEntityTypeArgs struct {
	// Log analytics entity type category. Category will be used for grouping and filtering.
	Category *string `pulumi:"category"`
	// Log analytics entity type name.
	Name *string `pulumi:"name"`
	// The Logging Analytics namespace used for the request.
	Namespace string `pulumi:"namespace"`
	// Log analytics entity type property definition.
	Properties []LogAnalyticsEntityTypeProperty `pulumi:"properties"`
}

// The set of arguments for constructing a LogAnalyticsEntityType resource.
type LogAnalyticsEntityTypeArgs struct {
	// Log analytics entity type category. Category will be used for grouping and filtering.
	Category pulumi.StringPtrInput
	// Log analytics entity type name.
	Name pulumi.StringPtrInput
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringInput
	// Log analytics entity type property definition.
	Properties LogAnalyticsEntityTypePropertyArrayInput
}

func (LogAnalyticsEntityTypeArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*logAnalyticsEntityTypeArgs)(nil)).Elem()
}

type LogAnalyticsEntityTypeInput interface {
	pulumi.Input

	ToLogAnalyticsEntityTypeOutput() LogAnalyticsEntityTypeOutput
	ToLogAnalyticsEntityTypeOutputWithContext(ctx context.Context) LogAnalyticsEntityTypeOutput
}

func (*LogAnalyticsEntityType) ElementType() reflect.Type {
	return reflect.TypeOf((**LogAnalyticsEntityType)(nil)).Elem()
}

func (i *LogAnalyticsEntityType) ToLogAnalyticsEntityTypeOutput() LogAnalyticsEntityTypeOutput {
	return i.ToLogAnalyticsEntityTypeOutputWithContext(context.Background())
}

func (i *LogAnalyticsEntityType) ToLogAnalyticsEntityTypeOutputWithContext(ctx context.Context) LogAnalyticsEntityTypeOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsEntityTypeOutput)
}

// LogAnalyticsEntityTypeArrayInput is an input type that accepts LogAnalyticsEntityTypeArray and LogAnalyticsEntityTypeArrayOutput values.
// You can construct a concrete instance of `LogAnalyticsEntityTypeArrayInput` via:
//
//	LogAnalyticsEntityTypeArray{ LogAnalyticsEntityTypeArgs{...} }
type LogAnalyticsEntityTypeArrayInput interface {
	pulumi.Input

	ToLogAnalyticsEntityTypeArrayOutput() LogAnalyticsEntityTypeArrayOutput
	ToLogAnalyticsEntityTypeArrayOutputWithContext(context.Context) LogAnalyticsEntityTypeArrayOutput
}

type LogAnalyticsEntityTypeArray []LogAnalyticsEntityTypeInput

func (LogAnalyticsEntityTypeArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LogAnalyticsEntityType)(nil)).Elem()
}

func (i LogAnalyticsEntityTypeArray) ToLogAnalyticsEntityTypeArrayOutput() LogAnalyticsEntityTypeArrayOutput {
	return i.ToLogAnalyticsEntityTypeArrayOutputWithContext(context.Background())
}

func (i LogAnalyticsEntityTypeArray) ToLogAnalyticsEntityTypeArrayOutputWithContext(ctx context.Context) LogAnalyticsEntityTypeArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsEntityTypeArrayOutput)
}

// LogAnalyticsEntityTypeMapInput is an input type that accepts LogAnalyticsEntityTypeMap and LogAnalyticsEntityTypeMapOutput values.
// You can construct a concrete instance of `LogAnalyticsEntityTypeMapInput` via:
//
//	LogAnalyticsEntityTypeMap{ "key": LogAnalyticsEntityTypeArgs{...} }
type LogAnalyticsEntityTypeMapInput interface {
	pulumi.Input

	ToLogAnalyticsEntityTypeMapOutput() LogAnalyticsEntityTypeMapOutput
	ToLogAnalyticsEntityTypeMapOutputWithContext(context.Context) LogAnalyticsEntityTypeMapOutput
}

type LogAnalyticsEntityTypeMap map[string]LogAnalyticsEntityTypeInput

func (LogAnalyticsEntityTypeMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LogAnalyticsEntityType)(nil)).Elem()
}

func (i LogAnalyticsEntityTypeMap) ToLogAnalyticsEntityTypeMapOutput() LogAnalyticsEntityTypeMapOutput {
	return i.ToLogAnalyticsEntityTypeMapOutputWithContext(context.Background())
}

func (i LogAnalyticsEntityTypeMap) ToLogAnalyticsEntityTypeMapOutputWithContext(ctx context.Context) LogAnalyticsEntityTypeMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsEntityTypeMapOutput)
}

type LogAnalyticsEntityTypeOutput struct{ *pulumi.OutputState }

func (LogAnalyticsEntityTypeOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**LogAnalyticsEntityType)(nil)).Elem()
}

func (o LogAnalyticsEntityTypeOutput) ToLogAnalyticsEntityTypeOutput() LogAnalyticsEntityTypeOutput {
	return o
}

func (o LogAnalyticsEntityTypeOutput) ToLogAnalyticsEntityTypeOutputWithContext(ctx context.Context) LogAnalyticsEntityTypeOutput {
	return o
}

// Log analytics entity type category. Category will be used for grouping and filtering.
func (o LogAnalyticsEntityTypeOutput) Category() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsEntityType) pulumi.StringOutput { return v.Category }).(pulumi.StringOutput)
}

// Log analytics entity type group. This can be CLOUD (OCI) or NON_CLOUD otherwise.
func (o LogAnalyticsEntityTypeOutput) CloudType() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsEntityType) pulumi.StringOutput { return v.CloudType }).(pulumi.StringOutput)
}

// Internal name for the log analytics entity type.
func (o LogAnalyticsEntityTypeOutput) InternalName() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsEntityType) pulumi.StringOutput { return v.InternalName }).(pulumi.StringOutput)
}

func (o LogAnalyticsEntityTypeOutput) ManagementAgentEligibilityStatus() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsEntityType) pulumi.StringOutput { return v.ManagementAgentEligibilityStatus }).(pulumi.StringOutput)
}

// Log analytics entity type name.
func (o LogAnalyticsEntityTypeOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsEntityType) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// The Logging Analytics namespace used for the request.
func (o LogAnalyticsEntityTypeOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsEntityType) pulumi.StringOutput { return v.Namespace }).(pulumi.StringOutput)
}

// Log analytics entity type property definition.
func (o LogAnalyticsEntityTypeOutput) Properties() LogAnalyticsEntityTypePropertyArrayOutput {
	return o.ApplyT(func(v *LogAnalyticsEntityType) LogAnalyticsEntityTypePropertyArrayOutput { return v.Properties }).(LogAnalyticsEntityTypePropertyArrayOutput)
}

// The current lifecycle state of the log analytics entity type.
func (o LogAnalyticsEntityTypeOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsEntityType) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Time the log analytics entity type was created. An RFC3339 formatted datetime string.
func (o LogAnalyticsEntityTypeOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsEntityType) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// Time the log analytics entity type was updated. An RFC3339 formatted datetime string.
func (o LogAnalyticsEntityTypeOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsEntityType) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type LogAnalyticsEntityTypeArrayOutput struct{ *pulumi.OutputState }

func (LogAnalyticsEntityTypeArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LogAnalyticsEntityType)(nil)).Elem()
}

func (o LogAnalyticsEntityTypeArrayOutput) ToLogAnalyticsEntityTypeArrayOutput() LogAnalyticsEntityTypeArrayOutput {
	return o
}

func (o LogAnalyticsEntityTypeArrayOutput) ToLogAnalyticsEntityTypeArrayOutputWithContext(ctx context.Context) LogAnalyticsEntityTypeArrayOutput {
	return o
}

func (o LogAnalyticsEntityTypeArrayOutput) Index(i pulumi.IntInput) LogAnalyticsEntityTypeOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *LogAnalyticsEntityType {
		return vs[0].([]*LogAnalyticsEntityType)[vs[1].(int)]
	}).(LogAnalyticsEntityTypeOutput)
}

type LogAnalyticsEntityTypeMapOutput struct{ *pulumi.OutputState }

func (LogAnalyticsEntityTypeMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LogAnalyticsEntityType)(nil)).Elem()
}

func (o LogAnalyticsEntityTypeMapOutput) ToLogAnalyticsEntityTypeMapOutput() LogAnalyticsEntityTypeMapOutput {
	return o
}

func (o LogAnalyticsEntityTypeMapOutput) ToLogAnalyticsEntityTypeMapOutputWithContext(ctx context.Context) LogAnalyticsEntityTypeMapOutput {
	return o
}

func (o LogAnalyticsEntityTypeMapOutput) MapIndex(k pulumi.StringInput) LogAnalyticsEntityTypeOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *LogAnalyticsEntityType {
		return vs[0].(map[string]*LogAnalyticsEntityType)[vs[1].(string)]
	}).(LogAnalyticsEntityTypeOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*LogAnalyticsEntityTypeInput)(nil)).Elem(), &LogAnalyticsEntityType{})
	pulumi.RegisterInputType(reflect.TypeOf((*LogAnalyticsEntityTypeArrayInput)(nil)).Elem(), LogAnalyticsEntityTypeArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*LogAnalyticsEntityTypeMapInput)(nil)).Elem(), LogAnalyticsEntityTypeMap{})
	pulumi.RegisterOutputType(LogAnalyticsEntityTypeOutput{})
	pulumi.RegisterOutputType(LogAnalyticsEntityTypeArrayOutput{})
	pulumi.RegisterOutputType(LogAnalyticsEntityTypeMapOutput{})
}
