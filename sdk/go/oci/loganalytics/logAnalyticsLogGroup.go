// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loganalytics

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Log Analytics Log Group resource in Oracle Cloud Infrastructure Log Analytics service.
//
// Creates a new log group in the specified compartment with the input display name. You may also specify optional information such as description, defined tags, and free-form tags.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/LogAnalytics"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := LogAnalytics.NewLogAnalyticsLogGroup(ctx, "testLogAnalyticsLogGroup", &LogAnalytics.LogAnalyticsLogGroupArgs{
//				CompartmentId: pulumi.Any(_var.Compartment_id),
//				DisplayName:   pulumi.Any(_var.Log_analytics_log_group_display_name),
//				Namespace:     pulumi.Any(_var.Log_analytics_log_group_namespace),
//				DefinedTags: pulumi.AnyMap{
//					"foo-namespace.bar-key": pulumi.Any("value"),
//				},
//				Description: pulumi.Any(_var.Log_analytics_log_group_description),
//				FreeformTags: pulumi.AnyMap{
//					"bar-key": pulumi.Any("value"),
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
// LogAnalyticsLogGroups can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:LogAnalytics/logAnalyticsLogGroup:LogAnalyticsLogGroup test_log_analytics_log_group "namespaces/{namespaceName}/logAnalyticsLogGroups/{logAnalyticsLogGroupId}"
//
// ```
type LogAnalyticsLogGroup struct {
	pulumi.CustomResourceState

	// (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Description for this resource.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringOutput `pulumi:"namespace"`
	// The date and time the resource was created, in the format defined by RFC3339.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the resource was last updated, in the format defined by RFC3339.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewLogAnalyticsLogGroup registers a new resource with the given unique name, arguments, and options.
func NewLogAnalyticsLogGroup(ctx *pulumi.Context,
	name string, args *LogAnalyticsLogGroupArgs, opts ...pulumi.ResourceOption) (*LogAnalyticsLogGroup, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.Namespace == nil {
		return nil, errors.New("invalid value for required argument 'Namespace'")
	}
	var resource LogAnalyticsLogGroup
	err := ctx.RegisterResource("oci:LogAnalytics/logAnalyticsLogGroup:LogAnalyticsLogGroup", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLogAnalyticsLogGroup gets an existing LogAnalyticsLogGroup resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLogAnalyticsLogGroup(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LogAnalyticsLogGroupState, opts ...pulumi.ResourceOption) (*LogAnalyticsLogGroup, error) {
	var resource LogAnalyticsLogGroup
	err := ctx.ReadResource("oci:LogAnalytics/logAnalyticsLogGroup:LogAnalyticsLogGroup", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LogAnalyticsLogGroup resources.
type logAnalyticsLogGroupState struct {
	// (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Description for this resource.
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The Logging Analytics namespace used for the request.
	Namespace *string `pulumi:"namespace"`
	// The date and time the resource was created, in the format defined by RFC3339.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the resource was last updated, in the format defined by RFC3339.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type LogAnalyticsLogGroupState struct {
	// (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Description for this resource.
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringPtrInput
	// The date and time the resource was created, in the format defined by RFC3339.
	TimeCreated pulumi.StringPtrInput
	// The date and time the resource was last updated, in the format defined by RFC3339.
	TimeUpdated pulumi.StringPtrInput
}

func (LogAnalyticsLogGroupState) ElementType() reflect.Type {
	return reflect.TypeOf((*logAnalyticsLogGroupState)(nil)).Elem()
}

type logAnalyticsLogGroupArgs struct {
	// (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Description for this resource.
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The Logging Analytics namespace used for the request.
	Namespace string `pulumi:"namespace"`
}

// The set of arguments for constructing a LogAnalyticsLogGroup resource.
type LogAnalyticsLogGroupArgs struct {
	// (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Description for this resource.
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringInput
}

func (LogAnalyticsLogGroupArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*logAnalyticsLogGroupArgs)(nil)).Elem()
}

type LogAnalyticsLogGroupInput interface {
	pulumi.Input

	ToLogAnalyticsLogGroupOutput() LogAnalyticsLogGroupOutput
	ToLogAnalyticsLogGroupOutputWithContext(ctx context.Context) LogAnalyticsLogGroupOutput
}

func (*LogAnalyticsLogGroup) ElementType() reflect.Type {
	return reflect.TypeOf((**LogAnalyticsLogGroup)(nil)).Elem()
}

func (i *LogAnalyticsLogGroup) ToLogAnalyticsLogGroupOutput() LogAnalyticsLogGroupOutput {
	return i.ToLogAnalyticsLogGroupOutputWithContext(context.Background())
}

func (i *LogAnalyticsLogGroup) ToLogAnalyticsLogGroupOutputWithContext(ctx context.Context) LogAnalyticsLogGroupOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsLogGroupOutput)
}

// LogAnalyticsLogGroupArrayInput is an input type that accepts LogAnalyticsLogGroupArray and LogAnalyticsLogGroupArrayOutput values.
// You can construct a concrete instance of `LogAnalyticsLogGroupArrayInput` via:
//
//	LogAnalyticsLogGroupArray{ LogAnalyticsLogGroupArgs{...} }
type LogAnalyticsLogGroupArrayInput interface {
	pulumi.Input

	ToLogAnalyticsLogGroupArrayOutput() LogAnalyticsLogGroupArrayOutput
	ToLogAnalyticsLogGroupArrayOutputWithContext(context.Context) LogAnalyticsLogGroupArrayOutput
}

type LogAnalyticsLogGroupArray []LogAnalyticsLogGroupInput

func (LogAnalyticsLogGroupArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LogAnalyticsLogGroup)(nil)).Elem()
}

func (i LogAnalyticsLogGroupArray) ToLogAnalyticsLogGroupArrayOutput() LogAnalyticsLogGroupArrayOutput {
	return i.ToLogAnalyticsLogGroupArrayOutputWithContext(context.Background())
}

func (i LogAnalyticsLogGroupArray) ToLogAnalyticsLogGroupArrayOutputWithContext(ctx context.Context) LogAnalyticsLogGroupArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsLogGroupArrayOutput)
}

// LogAnalyticsLogGroupMapInput is an input type that accepts LogAnalyticsLogGroupMap and LogAnalyticsLogGroupMapOutput values.
// You can construct a concrete instance of `LogAnalyticsLogGroupMapInput` via:
//
//	LogAnalyticsLogGroupMap{ "key": LogAnalyticsLogGroupArgs{...} }
type LogAnalyticsLogGroupMapInput interface {
	pulumi.Input

	ToLogAnalyticsLogGroupMapOutput() LogAnalyticsLogGroupMapOutput
	ToLogAnalyticsLogGroupMapOutputWithContext(context.Context) LogAnalyticsLogGroupMapOutput
}

type LogAnalyticsLogGroupMap map[string]LogAnalyticsLogGroupInput

func (LogAnalyticsLogGroupMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LogAnalyticsLogGroup)(nil)).Elem()
}

func (i LogAnalyticsLogGroupMap) ToLogAnalyticsLogGroupMapOutput() LogAnalyticsLogGroupMapOutput {
	return i.ToLogAnalyticsLogGroupMapOutputWithContext(context.Background())
}

func (i LogAnalyticsLogGroupMap) ToLogAnalyticsLogGroupMapOutputWithContext(ctx context.Context) LogAnalyticsLogGroupMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsLogGroupMapOutput)
}

type LogAnalyticsLogGroupOutput struct{ *pulumi.OutputState }

func (LogAnalyticsLogGroupOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**LogAnalyticsLogGroup)(nil)).Elem()
}

func (o LogAnalyticsLogGroupOutput) ToLogAnalyticsLogGroupOutput() LogAnalyticsLogGroupOutput {
	return o
}

func (o LogAnalyticsLogGroupOutput) ToLogAnalyticsLogGroupOutputWithContext(ctx context.Context) LogAnalyticsLogGroupOutput {
	return o
}

// (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
func (o LogAnalyticsLogGroupOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsLogGroup) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LogAnalyticsLogGroupOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *LogAnalyticsLogGroup) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) Description for this resource.
func (o LogAnalyticsLogGroupOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsLogGroup) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
func (o LogAnalyticsLogGroupOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsLogGroup) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LogAnalyticsLogGroupOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *LogAnalyticsLogGroup) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// The Logging Analytics namespace used for the request.
func (o LogAnalyticsLogGroupOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsLogGroup) pulumi.StringOutput { return v.Namespace }).(pulumi.StringOutput)
}

// The date and time the resource was created, in the format defined by RFC3339.
func (o LogAnalyticsLogGroupOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsLogGroup) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the resource was last updated, in the format defined by RFC3339.
func (o LogAnalyticsLogGroupOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsLogGroup) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type LogAnalyticsLogGroupArrayOutput struct{ *pulumi.OutputState }

func (LogAnalyticsLogGroupArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LogAnalyticsLogGroup)(nil)).Elem()
}

func (o LogAnalyticsLogGroupArrayOutput) ToLogAnalyticsLogGroupArrayOutput() LogAnalyticsLogGroupArrayOutput {
	return o
}

func (o LogAnalyticsLogGroupArrayOutput) ToLogAnalyticsLogGroupArrayOutputWithContext(ctx context.Context) LogAnalyticsLogGroupArrayOutput {
	return o
}

func (o LogAnalyticsLogGroupArrayOutput) Index(i pulumi.IntInput) LogAnalyticsLogGroupOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *LogAnalyticsLogGroup {
		return vs[0].([]*LogAnalyticsLogGroup)[vs[1].(int)]
	}).(LogAnalyticsLogGroupOutput)
}

type LogAnalyticsLogGroupMapOutput struct{ *pulumi.OutputState }

func (LogAnalyticsLogGroupMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LogAnalyticsLogGroup)(nil)).Elem()
}

func (o LogAnalyticsLogGroupMapOutput) ToLogAnalyticsLogGroupMapOutput() LogAnalyticsLogGroupMapOutput {
	return o
}

func (o LogAnalyticsLogGroupMapOutput) ToLogAnalyticsLogGroupMapOutputWithContext(ctx context.Context) LogAnalyticsLogGroupMapOutput {
	return o
}

func (o LogAnalyticsLogGroupMapOutput) MapIndex(k pulumi.StringInput) LogAnalyticsLogGroupOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *LogAnalyticsLogGroup {
		return vs[0].(map[string]*LogAnalyticsLogGroup)[vs[1].(string)]
	}).(LogAnalyticsLogGroupOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*LogAnalyticsLogGroupInput)(nil)).Elem(), &LogAnalyticsLogGroup{})
	pulumi.RegisterInputType(reflect.TypeOf((*LogAnalyticsLogGroupArrayInput)(nil)).Elem(), LogAnalyticsLogGroupArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*LogAnalyticsLogGroupMapInput)(nil)).Elem(), LogAnalyticsLogGroupMap{})
	pulumi.RegisterOutputType(LogAnalyticsLogGroupOutput{})
	pulumi.RegisterOutputType(LogAnalyticsLogGroupArrayOutput{})
	pulumi.RegisterOutputType(LogAnalyticsLogGroupMapOutput{})
}