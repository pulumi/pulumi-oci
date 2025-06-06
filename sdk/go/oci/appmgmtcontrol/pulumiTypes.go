// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package appmgmtcontrol

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

var _ = internal.GetEnvOrDefault

type GetMonitoredInstancesFilter struct {
	Name   string   `pulumi:"name"`
	Regex  *bool    `pulumi:"regex"`
	Values []string `pulumi:"values"`
}

// GetMonitoredInstancesFilterInput is an input type that accepts GetMonitoredInstancesFilterArgs and GetMonitoredInstancesFilterOutput values.
// You can construct a concrete instance of `GetMonitoredInstancesFilterInput` via:
//
//	GetMonitoredInstancesFilterArgs{...}
type GetMonitoredInstancesFilterInput interface {
	pulumi.Input

	ToGetMonitoredInstancesFilterOutput() GetMonitoredInstancesFilterOutput
	ToGetMonitoredInstancesFilterOutputWithContext(context.Context) GetMonitoredInstancesFilterOutput
}

type GetMonitoredInstancesFilterArgs struct {
	Name   pulumi.StringInput      `pulumi:"name"`
	Regex  pulumi.BoolPtrInput     `pulumi:"regex"`
	Values pulumi.StringArrayInput `pulumi:"values"`
}

func (GetMonitoredInstancesFilterArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMonitoredInstancesFilter)(nil)).Elem()
}

func (i GetMonitoredInstancesFilterArgs) ToGetMonitoredInstancesFilterOutput() GetMonitoredInstancesFilterOutput {
	return i.ToGetMonitoredInstancesFilterOutputWithContext(context.Background())
}

func (i GetMonitoredInstancesFilterArgs) ToGetMonitoredInstancesFilterOutputWithContext(ctx context.Context) GetMonitoredInstancesFilterOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetMonitoredInstancesFilterOutput)
}

// GetMonitoredInstancesFilterArrayInput is an input type that accepts GetMonitoredInstancesFilterArray and GetMonitoredInstancesFilterArrayOutput values.
// You can construct a concrete instance of `GetMonitoredInstancesFilterArrayInput` via:
//
//	GetMonitoredInstancesFilterArray{ GetMonitoredInstancesFilterArgs{...} }
type GetMonitoredInstancesFilterArrayInput interface {
	pulumi.Input

	ToGetMonitoredInstancesFilterArrayOutput() GetMonitoredInstancesFilterArrayOutput
	ToGetMonitoredInstancesFilterArrayOutputWithContext(context.Context) GetMonitoredInstancesFilterArrayOutput
}

type GetMonitoredInstancesFilterArray []GetMonitoredInstancesFilterInput

func (GetMonitoredInstancesFilterArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetMonitoredInstancesFilter)(nil)).Elem()
}

func (i GetMonitoredInstancesFilterArray) ToGetMonitoredInstancesFilterArrayOutput() GetMonitoredInstancesFilterArrayOutput {
	return i.ToGetMonitoredInstancesFilterArrayOutputWithContext(context.Background())
}

func (i GetMonitoredInstancesFilterArray) ToGetMonitoredInstancesFilterArrayOutputWithContext(ctx context.Context) GetMonitoredInstancesFilterArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetMonitoredInstancesFilterArrayOutput)
}

type GetMonitoredInstancesFilterOutput struct{ *pulumi.OutputState }

func (GetMonitoredInstancesFilterOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMonitoredInstancesFilter)(nil)).Elem()
}

func (o GetMonitoredInstancesFilterOutput) ToGetMonitoredInstancesFilterOutput() GetMonitoredInstancesFilterOutput {
	return o
}

func (o GetMonitoredInstancesFilterOutput) ToGetMonitoredInstancesFilterOutputWithContext(ctx context.Context) GetMonitoredInstancesFilterOutput {
	return o
}

func (o GetMonitoredInstancesFilterOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v GetMonitoredInstancesFilter) string { return v.Name }).(pulumi.StringOutput)
}

func (o GetMonitoredInstancesFilterOutput) Regex() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetMonitoredInstancesFilter) *bool { return v.Regex }).(pulumi.BoolPtrOutput)
}

func (o GetMonitoredInstancesFilterOutput) Values() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetMonitoredInstancesFilter) []string { return v.Values }).(pulumi.StringArrayOutput)
}

type GetMonitoredInstancesFilterArrayOutput struct{ *pulumi.OutputState }

func (GetMonitoredInstancesFilterArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetMonitoredInstancesFilter)(nil)).Elem()
}

func (o GetMonitoredInstancesFilterArrayOutput) ToGetMonitoredInstancesFilterArrayOutput() GetMonitoredInstancesFilterArrayOutput {
	return o
}

func (o GetMonitoredInstancesFilterArrayOutput) ToGetMonitoredInstancesFilterArrayOutputWithContext(ctx context.Context) GetMonitoredInstancesFilterArrayOutput {
	return o
}

func (o GetMonitoredInstancesFilterArrayOutput) Index(i pulumi.IntInput) GetMonitoredInstancesFilterOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) GetMonitoredInstancesFilter {
		return vs[0].([]GetMonitoredInstancesFilter)[vs[1].(int)]
	}).(GetMonitoredInstancesFilterOutput)
}

type GetMonitoredInstancesMonitoredInstanceCollection struct {
	Items []GetMonitoredInstancesMonitoredInstanceCollectionItem `pulumi:"items"`
}

// GetMonitoredInstancesMonitoredInstanceCollectionInput is an input type that accepts GetMonitoredInstancesMonitoredInstanceCollectionArgs and GetMonitoredInstancesMonitoredInstanceCollectionOutput values.
// You can construct a concrete instance of `GetMonitoredInstancesMonitoredInstanceCollectionInput` via:
//
//	GetMonitoredInstancesMonitoredInstanceCollectionArgs{...}
type GetMonitoredInstancesMonitoredInstanceCollectionInput interface {
	pulumi.Input

	ToGetMonitoredInstancesMonitoredInstanceCollectionOutput() GetMonitoredInstancesMonitoredInstanceCollectionOutput
	ToGetMonitoredInstancesMonitoredInstanceCollectionOutputWithContext(context.Context) GetMonitoredInstancesMonitoredInstanceCollectionOutput
}

type GetMonitoredInstancesMonitoredInstanceCollectionArgs struct {
	Items GetMonitoredInstancesMonitoredInstanceCollectionItemArrayInput `pulumi:"items"`
}

func (GetMonitoredInstancesMonitoredInstanceCollectionArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMonitoredInstancesMonitoredInstanceCollection)(nil)).Elem()
}

func (i GetMonitoredInstancesMonitoredInstanceCollectionArgs) ToGetMonitoredInstancesMonitoredInstanceCollectionOutput() GetMonitoredInstancesMonitoredInstanceCollectionOutput {
	return i.ToGetMonitoredInstancesMonitoredInstanceCollectionOutputWithContext(context.Background())
}

func (i GetMonitoredInstancesMonitoredInstanceCollectionArgs) ToGetMonitoredInstancesMonitoredInstanceCollectionOutputWithContext(ctx context.Context) GetMonitoredInstancesMonitoredInstanceCollectionOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetMonitoredInstancesMonitoredInstanceCollectionOutput)
}

// GetMonitoredInstancesMonitoredInstanceCollectionArrayInput is an input type that accepts GetMonitoredInstancesMonitoredInstanceCollectionArray and GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput values.
// You can construct a concrete instance of `GetMonitoredInstancesMonitoredInstanceCollectionArrayInput` via:
//
//	GetMonitoredInstancesMonitoredInstanceCollectionArray{ GetMonitoredInstancesMonitoredInstanceCollectionArgs{...} }
type GetMonitoredInstancesMonitoredInstanceCollectionArrayInput interface {
	pulumi.Input

	ToGetMonitoredInstancesMonitoredInstanceCollectionArrayOutput() GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput
	ToGetMonitoredInstancesMonitoredInstanceCollectionArrayOutputWithContext(context.Context) GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput
}

type GetMonitoredInstancesMonitoredInstanceCollectionArray []GetMonitoredInstancesMonitoredInstanceCollectionInput

func (GetMonitoredInstancesMonitoredInstanceCollectionArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetMonitoredInstancesMonitoredInstanceCollection)(nil)).Elem()
}

func (i GetMonitoredInstancesMonitoredInstanceCollectionArray) ToGetMonitoredInstancesMonitoredInstanceCollectionArrayOutput() GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput {
	return i.ToGetMonitoredInstancesMonitoredInstanceCollectionArrayOutputWithContext(context.Background())
}

func (i GetMonitoredInstancesMonitoredInstanceCollectionArray) ToGetMonitoredInstancesMonitoredInstanceCollectionArrayOutputWithContext(ctx context.Context) GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput)
}

type GetMonitoredInstancesMonitoredInstanceCollectionOutput struct{ *pulumi.OutputState }

func (GetMonitoredInstancesMonitoredInstanceCollectionOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMonitoredInstancesMonitoredInstanceCollection)(nil)).Elem()
}

func (o GetMonitoredInstancesMonitoredInstanceCollectionOutput) ToGetMonitoredInstancesMonitoredInstanceCollectionOutput() GetMonitoredInstancesMonitoredInstanceCollectionOutput {
	return o
}

func (o GetMonitoredInstancesMonitoredInstanceCollectionOutput) ToGetMonitoredInstancesMonitoredInstanceCollectionOutputWithContext(ctx context.Context) GetMonitoredInstancesMonitoredInstanceCollectionOutput {
	return o
}

func (o GetMonitoredInstancesMonitoredInstanceCollectionOutput) Items() GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput {
	return o.ApplyT(func(v GetMonitoredInstancesMonitoredInstanceCollection) []GetMonitoredInstancesMonitoredInstanceCollectionItem {
		return v.Items
	}).(GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput)
}

type GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput struct{ *pulumi.OutputState }

func (GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetMonitoredInstancesMonitoredInstanceCollection)(nil)).Elem()
}

func (o GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput) ToGetMonitoredInstancesMonitoredInstanceCollectionArrayOutput() GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput {
	return o
}

func (o GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput) ToGetMonitoredInstancesMonitoredInstanceCollectionArrayOutputWithContext(ctx context.Context) GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput {
	return o
}

func (o GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput) Index(i pulumi.IntInput) GetMonitoredInstancesMonitoredInstanceCollectionOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) GetMonitoredInstancesMonitoredInstanceCollection {
		return vs[0].([]GetMonitoredInstancesMonitoredInstanceCollection)[vs[1].(int)]
	}).(GetMonitoredInstancesMonitoredInstanceCollectionOutput)
}

type GetMonitoredInstancesMonitoredInstanceCollectionItem struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored instance.
	InstanceId string `pulumi:"instanceId"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Used to invoke manage operations on Management Agent Cloud Service.
	ManagementAgentId string `pulumi:"managementAgentId"`
	// Monitoring status. Can be either enabled or disabled.
	MonitoringState string `pulumi:"monitoringState"`
	// The current state of the monitored instance.
	State string `pulumi:"state"`
	// The time the MonitoredInstance was created. An RFC3339 formatted datetime string
	TimeCreated string `pulumi:"timeCreated"`
	// The time the MonitoredInstance was updated. An RFC3339 formatted datetime string
	TimeUpdated string `pulumi:"timeUpdated"`
}

// GetMonitoredInstancesMonitoredInstanceCollectionItemInput is an input type that accepts GetMonitoredInstancesMonitoredInstanceCollectionItemArgs and GetMonitoredInstancesMonitoredInstanceCollectionItemOutput values.
// You can construct a concrete instance of `GetMonitoredInstancesMonitoredInstanceCollectionItemInput` via:
//
//	GetMonitoredInstancesMonitoredInstanceCollectionItemArgs{...}
type GetMonitoredInstancesMonitoredInstanceCollectionItemInput interface {
	pulumi.Input

	ToGetMonitoredInstancesMonitoredInstanceCollectionItemOutput() GetMonitoredInstancesMonitoredInstanceCollectionItemOutput
	ToGetMonitoredInstancesMonitoredInstanceCollectionItemOutputWithContext(context.Context) GetMonitoredInstancesMonitoredInstanceCollectionItemOutput
}

type GetMonitoredInstancesMonitoredInstanceCollectionItemArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringInput `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored instance.
	InstanceId pulumi.StringInput `pulumi:"instanceId"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringInput `pulumi:"lifecycleDetails"`
	// Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Used to invoke manage operations on Management Agent Cloud Service.
	ManagementAgentId pulumi.StringInput `pulumi:"managementAgentId"`
	// Monitoring status. Can be either enabled or disabled.
	MonitoringState pulumi.StringInput `pulumi:"monitoringState"`
	// The current state of the monitored instance.
	State pulumi.StringInput `pulumi:"state"`
	// The time the MonitoredInstance was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringInput `pulumi:"timeCreated"`
	// The time the MonitoredInstance was updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringInput `pulumi:"timeUpdated"`
}

func (GetMonitoredInstancesMonitoredInstanceCollectionItemArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMonitoredInstancesMonitoredInstanceCollectionItem)(nil)).Elem()
}

func (i GetMonitoredInstancesMonitoredInstanceCollectionItemArgs) ToGetMonitoredInstancesMonitoredInstanceCollectionItemOutput() GetMonitoredInstancesMonitoredInstanceCollectionItemOutput {
	return i.ToGetMonitoredInstancesMonitoredInstanceCollectionItemOutputWithContext(context.Background())
}

func (i GetMonitoredInstancesMonitoredInstanceCollectionItemArgs) ToGetMonitoredInstancesMonitoredInstanceCollectionItemOutputWithContext(ctx context.Context) GetMonitoredInstancesMonitoredInstanceCollectionItemOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetMonitoredInstancesMonitoredInstanceCollectionItemOutput)
}

// GetMonitoredInstancesMonitoredInstanceCollectionItemArrayInput is an input type that accepts GetMonitoredInstancesMonitoredInstanceCollectionItemArray and GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput values.
// You can construct a concrete instance of `GetMonitoredInstancesMonitoredInstanceCollectionItemArrayInput` via:
//
//	GetMonitoredInstancesMonitoredInstanceCollectionItemArray{ GetMonitoredInstancesMonitoredInstanceCollectionItemArgs{...} }
type GetMonitoredInstancesMonitoredInstanceCollectionItemArrayInput interface {
	pulumi.Input

	ToGetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput() GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput
	ToGetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutputWithContext(context.Context) GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput
}

type GetMonitoredInstancesMonitoredInstanceCollectionItemArray []GetMonitoredInstancesMonitoredInstanceCollectionItemInput

func (GetMonitoredInstancesMonitoredInstanceCollectionItemArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetMonitoredInstancesMonitoredInstanceCollectionItem)(nil)).Elem()
}

func (i GetMonitoredInstancesMonitoredInstanceCollectionItemArray) ToGetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput() GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput {
	return i.ToGetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutputWithContext(context.Background())
}

func (i GetMonitoredInstancesMonitoredInstanceCollectionItemArray) ToGetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutputWithContext(ctx context.Context) GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput)
}

type GetMonitoredInstancesMonitoredInstanceCollectionItemOutput struct{ *pulumi.OutputState }

func (GetMonitoredInstancesMonitoredInstanceCollectionItemOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMonitoredInstancesMonitoredInstanceCollectionItem)(nil)).Elem()
}

func (o GetMonitoredInstancesMonitoredInstanceCollectionItemOutput) ToGetMonitoredInstancesMonitoredInstanceCollectionItemOutput() GetMonitoredInstancesMonitoredInstanceCollectionItemOutput {
	return o
}

func (o GetMonitoredInstancesMonitoredInstanceCollectionItemOutput) ToGetMonitoredInstancesMonitoredInstanceCollectionItemOutputWithContext(ctx context.Context) GetMonitoredInstancesMonitoredInstanceCollectionItemOutput {
	return o
}

// The ID of the compartment in which to list resources.
func (o GetMonitoredInstancesMonitoredInstanceCollectionItemOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetMonitoredInstancesMonitoredInstanceCollectionItem) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A filter to return only resources that match the entire display name given.
func (o GetMonitoredInstancesMonitoredInstanceCollectionItemOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v GetMonitoredInstancesMonitoredInstanceCollectionItem) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored instance.
func (o GetMonitoredInstancesMonitoredInstanceCollectionItemOutput) InstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v GetMonitoredInstancesMonitoredInstanceCollectionItem) string { return v.InstanceId }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o GetMonitoredInstancesMonitoredInstanceCollectionItemOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v GetMonitoredInstancesMonitoredInstanceCollectionItem) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Used to invoke manage operations on Management Agent Cloud Service.
func (o GetMonitoredInstancesMonitoredInstanceCollectionItemOutput) ManagementAgentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetMonitoredInstancesMonitoredInstanceCollectionItem) string { return v.ManagementAgentId }).(pulumi.StringOutput)
}

// Monitoring status. Can be either enabled or disabled.
func (o GetMonitoredInstancesMonitoredInstanceCollectionItemOutput) MonitoringState() pulumi.StringOutput {
	return o.ApplyT(func(v GetMonitoredInstancesMonitoredInstanceCollectionItem) string { return v.MonitoringState }).(pulumi.StringOutput)
}

// The current state of the monitored instance.
func (o GetMonitoredInstancesMonitoredInstanceCollectionItemOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetMonitoredInstancesMonitoredInstanceCollectionItem) string { return v.State }).(pulumi.StringOutput)
}

// The time the MonitoredInstance was created. An RFC3339 formatted datetime string
func (o GetMonitoredInstancesMonitoredInstanceCollectionItemOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetMonitoredInstancesMonitoredInstanceCollectionItem) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the MonitoredInstance was updated. An RFC3339 formatted datetime string
func (o GetMonitoredInstancesMonitoredInstanceCollectionItemOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v GetMonitoredInstancesMonitoredInstanceCollectionItem) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

type GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput struct{ *pulumi.OutputState }

func (GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetMonitoredInstancesMonitoredInstanceCollectionItem)(nil)).Elem()
}

func (o GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput) ToGetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput() GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput {
	return o
}

func (o GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput) ToGetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutputWithContext(ctx context.Context) GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput {
	return o
}

func (o GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput) Index(i pulumi.IntInput) GetMonitoredInstancesMonitoredInstanceCollectionItemOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) GetMonitoredInstancesMonitoredInstanceCollectionItem {
		return vs[0].([]GetMonitoredInstancesMonitoredInstanceCollectionItem)[vs[1].(int)]
	}).(GetMonitoredInstancesMonitoredInstanceCollectionItemOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*GetMonitoredInstancesFilterInput)(nil)).Elem(), GetMonitoredInstancesFilterArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*GetMonitoredInstancesFilterArrayInput)(nil)).Elem(), GetMonitoredInstancesFilterArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*GetMonitoredInstancesMonitoredInstanceCollectionInput)(nil)).Elem(), GetMonitoredInstancesMonitoredInstanceCollectionArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*GetMonitoredInstancesMonitoredInstanceCollectionArrayInput)(nil)).Elem(), GetMonitoredInstancesMonitoredInstanceCollectionArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*GetMonitoredInstancesMonitoredInstanceCollectionItemInput)(nil)).Elem(), GetMonitoredInstancesMonitoredInstanceCollectionItemArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*GetMonitoredInstancesMonitoredInstanceCollectionItemArrayInput)(nil)).Elem(), GetMonitoredInstancesMonitoredInstanceCollectionItemArray{})
	pulumi.RegisterOutputType(GetMonitoredInstancesFilterOutput{})
	pulumi.RegisterOutputType(GetMonitoredInstancesFilterArrayOutput{})
	pulumi.RegisterOutputType(GetMonitoredInstancesMonitoredInstanceCollectionOutput{})
	pulumi.RegisterOutputType(GetMonitoredInstancesMonitoredInstanceCollectionArrayOutput{})
	pulumi.RegisterOutputType(GetMonitoredInstancesMonitoredInstanceCollectionItemOutput{})
	pulumi.RegisterOutputType(GetMonitoredInstancesMonitoredInstanceCollectionItemArrayOutput{})
}
