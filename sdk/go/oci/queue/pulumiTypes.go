// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package queue

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type GetQueuesFilter struct {
	Name   string   `pulumi:"name"`
	Regex  *bool    `pulumi:"regex"`
	Values []string `pulumi:"values"`
}

// GetQueuesFilterInput is an input type that accepts GetQueuesFilterArgs and GetQueuesFilterOutput values.
// You can construct a concrete instance of `GetQueuesFilterInput` via:
//
//	GetQueuesFilterArgs{...}
type GetQueuesFilterInput interface {
	pulumi.Input

	ToGetQueuesFilterOutput() GetQueuesFilterOutput
	ToGetQueuesFilterOutputWithContext(context.Context) GetQueuesFilterOutput
}

type GetQueuesFilterArgs struct {
	Name   pulumi.StringInput      `pulumi:"name"`
	Regex  pulumi.BoolPtrInput     `pulumi:"regex"`
	Values pulumi.StringArrayInput `pulumi:"values"`
}

func (GetQueuesFilterArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetQueuesFilter)(nil)).Elem()
}

func (i GetQueuesFilterArgs) ToGetQueuesFilterOutput() GetQueuesFilterOutput {
	return i.ToGetQueuesFilterOutputWithContext(context.Background())
}

func (i GetQueuesFilterArgs) ToGetQueuesFilterOutputWithContext(ctx context.Context) GetQueuesFilterOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetQueuesFilterOutput)
}

// GetQueuesFilterArrayInput is an input type that accepts GetQueuesFilterArray and GetQueuesFilterArrayOutput values.
// You can construct a concrete instance of `GetQueuesFilterArrayInput` via:
//
//	GetQueuesFilterArray{ GetQueuesFilterArgs{...} }
type GetQueuesFilterArrayInput interface {
	pulumi.Input

	ToGetQueuesFilterArrayOutput() GetQueuesFilterArrayOutput
	ToGetQueuesFilterArrayOutputWithContext(context.Context) GetQueuesFilterArrayOutput
}

type GetQueuesFilterArray []GetQueuesFilterInput

func (GetQueuesFilterArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetQueuesFilter)(nil)).Elem()
}

func (i GetQueuesFilterArray) ToGetQueuesFilterArrayOutput() GetQueuesFilterArrayOutput {
	return i.ToGetQueuesFilterArrayOutputWithContext(context.Background())
}

func (i GetQueuesFilterArray) ToGetQueuesFilterArrayOutputWithContext(ctx context.Context) GetQueuesFilterArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetQueuesFilterArrayOutput)
}

type GetQueuesFilterOutput struct{ *pulumi.OutputState }

func (GetQueuesFilterOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetQueuesFilter)(nil)).Elem()
}

func (o GetQueuesFilterOutput) ToGetQueuesFilterOutput() GetQueuesFilterOutput {
	return o
}

func (o GetQueuesFilterOutput) ToGetQueuesFilterOutputWithContext(ctx context.Context) GetQueuesFilterOutput {
	return o
}

func (o GetQueuesFilterOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v GetQueuesFilter) string { return v.Name }).(pulumi.StringOutput)
}

func (o GetQueuesFilterOutput) Regex() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetQueuesFilter) *bool { return v.Regex }).(pulumi.BoolPtrOutput)
}

func (o GetQueuesFilterOutput) Values() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetQueuesFilter) []string { return v.Values }).(pulumi.StringArrayOutput)
}

type GetQueuesFilterArrayOutput struct{ *pulumi.OutputState }

func (GetQueuesFilterArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetQueuesFilter)(nil)).Elem()
}

func (o GetQueuesFilterArrayOutput) ToGetQueuesFilterArrayOutput() GetQueuesFilterArrayOutput {
	return o
}

func (o GetQueuesFilterArrayOutput) ToGetQueuesFilterArrayOutputWithContext(ctx context.Context) GetQueuesFilterArrayOutput {
	return o
}

func (o GetQueuesFilterArrayOutput) Index(i pulumi.IntInput) GetQueuesFilterOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) GetQueuesFilter {
		return vs[0].([]GetQueuesFilter)[vs[1].(int)]
	}).(GetQueuesFilterOutput)
}

type GetQueuesQueueCollection struct {
	Items []GetQueuesQueueCollectionItem `pulumi:"items"`
}

// GetQueuesQueueCollectionInput is an input type that accepts GetQueuesQueueCollectionArgs and GetQueuesQueueCollectionOutput values.
// You can construct a concrete instance of `GetQueuesQueueCollectionInput` via:
//
//	GetQueuesQueueCollectionArgs{...}
type GetQueuesQueueCollectionInput interface {
	pulumi.Input

	ToGetQueuesQueueCollectionOutput() GetQueuesQueueCollectionOutput
	ToGetQueuesQueueCollectionOutputWithContext(context.Context) GetQueuesQueueCollectionOutput
}

type GetQueuesQueueCollectionArgs struct {
	Items GetQueuesQueueCollectionItemArrayInput `pulumi:"items"`
}

func (GetQueuesQueueCollectionArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetQueuesQueueCollection)(nil)).Elem()
}

func (i GetQueuesQueueCollectionArgs) ToGetQueuesQueueCollectionOutput() GetQueuesQueueCollectionOutput {
	return i.ToGetQueuesQueueCollectionOutputWithContext(context.Background())
}

func (i GetQueuesQueueCollectionArgs) ToGetQueuesQueueCollectionOutputWithContext(ctx context.Context) GetQueuesQueueCollectionOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetQueuesQueueCollectionOutput)
}

// GetQueuesQueueCollectionArrayInput is an input type that accepts GetQueuesQueueCollectionArray and GetQueuesQueueCollectionArrayOutput values.
// You can construct a concrete instance of `GetQueuesQueueCollectionArrayInput` via:
//
//	GetQueuesQueueCollectionArray{ GetQueuesQueueCollectionArgs{...} }
type GetQueuesQueueCollectionArrayInput interface {
	pulumi.Input

	ToGetQueuesQueueCollectionArrayOutput() GetQueuesQueueCollectionArrayOutput
	ToGetQueuesQueueCollectionArrayOutputWithContext(context.Context) GetQueuesQueueCollectionArrayOutput
}

type GetQueuesQueueCollectionArray []GetQueuesQueueCollectionInput

func (GetQueuesQueueCollectionArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetQueuesQueueCollection)(nil)).Elem()
}

func (i GetQueuesQueueCollectionArray) ToGetQueuesQueueCollectionArrayOutput() GetQueuesQueueCollectionArrayOutput {
	return i.ToGetQueuesQueueCollectionArrayOutputWithContext(context.Background())
}

func (i GetQueuesQueueCollectionArray) ToGetQueuesQueueCollectionArrayOutputWithContext(ctx context.Context) GetQueuesQueueCollectionArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetQueuesQueueCollectionArrayOutput)
}

type GetQueuesQueueCollectionOutput struct{ *pulumi.OutputState }

func (GetQueuesQueueCollectionOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetQueuesQueueCollection)(nil)).Elem()
}

func (o GetQueuesQueueCollectionOutput) ToGetQueuesQueueCollectionOutput() GetQueuesQueueCollectionOutput {
	return o
}

func (o GetQueuesQueueCollectionOutput) ToGetQueuesQueueCollectionOutputWithContext(ctx context.Context) GetQueuesQueueCollectionOutput {
	return o
}

func (o GetQueuesQueueCollectionOutput) Items() GetQueuesQueueCollectionItemArrayOutput {
	return o.ApplyT(func(v GetQueuesQueueCollection) []GetQueuesQueueCollectionItem { return v.Items }).(GetQueuesQueueCollectionItemArrayOutput)
}

type GetQueuesQueueCollectionArrayOutput struct{ *pulumi.OutputState }

func (GetQueuesQueueCollectionArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetQueuesQueueCollection)(nil)).Elem()
}

func (o GetQueuesQueueCollectionArrayOutput) ToGetQueuesQueueCollectionArrayOutput() GetQueuesQueueCollectionArrayOutput {
	return o
}

func (o GetQueuesQueueCollectionArrayOutput) ToGetQueuesQueueCollectionArrayOutputWithContext(ctx context.Context) GetQueuesQueueCollectionArrayOutput {
	return o
}

func (o GetQueuesQueueCollectionArrayOutput) Index(i pulumi.IntInput) GetQueuesQueueCollectionOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) GetQueuesQueueCollection {
		return vs[0].([]GetQueuesQueueCollection)[vs[1].(int)]
	}).(GetQueuesQueueCollectionOutput)
}

type GetQueuesQueueCollectionItem struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// Id of the custom master encryption key which will be used to encrypt messages content
	CustomEncryptionKeyId string `pulumi:"customEncryptionKeyId"`
	// The number of times a message can be delivered to a consumer before being moved to the dead letter queue. A value of 0 indicates that the DLQ is not used.
	DeadLetterQueueDeliveryCount int `pulumi:"deadLetterQueueDeliveryCount"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A filter to return only resources that match the entire display name given.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// unique Queue identifier
	Id string `pulumi:"id"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The endpoint to use to consume or publish messages in the queue.
	MessagesEndpoint string `pulumi:"messagesEndpoint"`
	PurgeQueue       bool   `pulumi:"purgeQueue"`
	PurgeType        string `pulumi:"purgeType"`
	// The retention period of the messages in the queue, in seconds.
	RetentionInSeconds int `pulumi:"retentionInSeconds"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The time the the Queue was created. An RFC3339 formatted datetime string
	TimeCreated string `pulumi:"timeCreated"`
	// The time the Queue was updated. An RFC3339 formatted datetime string
	TimeUpdated string `pulumi:"timeUpdated"`
	// The default polling timeout of the messages in the queue, in seconds.
	TimeoutInSeconds int `pulumi:"timeoutInSeconds"`
	// The default visibility of the messages consumed from the queue.
	VisibilityInSeconds int `pulumi:"visibilityInSeconds"`
}

// GetQueuesQueueCollectionItemInput is an input type that accepts GetQueuesQueueCollectionItemArgs and GetQueuesQueueCollectionItemOutput values.
// You can construct a concrete instance of `GetQueuesQueueCollectionItemInput` via:
//
//	GetQueuesQueueCollectionItemArgs{...}
type GetQueuesQueueCollectionItemInput interface {
	pulumi.Input

	ToGetQueuesQueueCollectionItemOutput() GetQueuesQueueCollectionItemOutput
	ToGetQueuesQueueCollectionItemOutputWithContext(context.Context) GetQueuesQueueCollectionItemOutput
}

type GetQueuesQueueCollectionItemArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Id of the custom master encryption key which will be used to encrypt messages content
	CustomEncryptionKeyId pulumi.StringInput `pulumi:"customEncryptionKeyId"`
	// The number of times a message can be delivered to a consumer before being moved to the dead letter queue. A value of 0 indicates that the DLQ is not used.
	DeadLetterQueueDeliveryCount pulumi.IntInput `pulumi:"deadLetterQueueDeliveryCount"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput `pulumi:"definedTags"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringInput `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput `pulumi:"freeformTags"`
	// unique Queue identifier
	Id pulumi.StringInput `pulumi:"id"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringInput `pulumi:"lifecycleDetails"`
	// The endpoint to use to consume or publish messages in the queue.
	MessagesEndpoint pulumi.StringInput `pulumi:"messagesEndpoint"`
	PurgeQueue       pulumi.BoolInput   `pulumi:"purgeQueue"`
	PurgeType        pulumi.StringInput `pulumi:"purgeType"`
	// The retention period of the messages in the queue, in seconds.
	RetentionInSeconds pulumi.IntInput `pulumi:"retentionInSeconds"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State pulumi.StringInput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput `pulumi:"systemTags"`
	// The time the the Queue was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringInput `pulumi:"timeCreated"`
	// The time the Queue was updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringInput `pulumi:"timeUpdated"`
	// The default polling timeout of the messages in the queue, in seconds.
	TimeoutInSeconds pulumi.IntInput `pulumi:"timeoutInSeconds"`
	// The default visibility of the messages consumed from the queue.
	VisibilityInSeconds pulumi.IntInput `pulumi:"visibilityInSeconds"`
}

func (GetQueuesQueueCollectionItemArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetQueuesQueueCollectionItem)(nil)).Elem()
}

func (i GetQueuesQueueCollectionItemArgs) ToGetQueuesQueueCollectionItemOutput() GetQueuesQueueCollectionItemOutput {
	return i.ToGetQueuesQueueCollectionItemOutputWithContext(context.Background())
}

func (i GetQueuesQueueCollectionItemArgs) ToGetQueuesQueueCollectionItemOutputWithContext(ctx context.Context) GetQueuesQueueCollectionItemOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetQueuesQueueCollectionItemOutput)
}

// GetQueuesQueueCollectionItemArrayInput is an input type that accepts GetQueuesQueueCollectionItemArray and GetQueuesQueueCollectionItemArrayOutput values.
// You can construct a concrete instance of `GetQueuesQueueCollectionItemArrayInput` via:
//
//	GetQueuesQueueCollectionItemArray{ GetQueuesQueueCollectionItemArgs{...} }
type GetQueuesQueueCollectionItemArrayInput interface {
	pulumi.Input

	ToGetQueuesQueueCollectionItemArrayOutput() GetQueuesQueueCollectionItemArrayOutput
	ToGetQueuesQueueCollectionItemArrayOutputWithContext(context.Context) GetQueuesQueueCollectionItemArrayOutput
}

type GetQueuesQueueCollectionItemArray []GetQueuesQueueCollectionItemInput

func (GetQueuesQueueCollectionItemArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetQueuesQueueCollectionItem)(nil)).Elem()
}

func (i GetQueuesQueueCollectionItemArray) ToGetQueuesQueueCollectionItemArrayOutput() GetQueuesQueueCollectionItemArrayOutput {
	return i.ToGetQueuesQueueCollectionItemArrayOutputWithContext(context.Background())
}

func (i GetQueuesQueueCollectionItemArray) ToGetQueuesQueueCollectionItemArrayOutputWithContext(ctx context.Context) GetQueuesQueueCollectionItemArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetQueuesQueueCollectionItemArrayOutput)
}

type GetQueuesQueueCollectionItemOutput struct{ *pulumi.OutputState }

func (GetQueuesQueueCollectionItemOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetQueuesQueueCollectionItem)(nil)).Elem()
}

func (o GetQueuesQueueCollectionItemOutput) ToGetQueuesQueueCollectionItemOutput() GetQueuesQueueCollectionItemOutput {
	return o
}

func (o GetQueuesQueueCollectionItemOutput) ToGetQueuesQueueCollectionItemOutputWithContext(ctx context.Context) GetQueuesQueueCollectionItemOutput {
	return o
}

// The ID of the compartment in which to list resources.
func (o GetQueuesQueueCollectionItemOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Id of the custom master encryption key which will be used to encrypt messages content
func (o GetQueuesQueueCollectionItemOutput) CustomEncryptionKeyId() pulumi.StringOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) string { return v.CustomEncryptionKeyId }).(pulumi.StringOutput)
}

// The number of times a message can be delivered to a consumer before being moved to the dead letter queue. A value of 0 indicates that the DLQ is not used.
func (o GetQueuesQueueCollectionItemOutput) DeadLetterQueueDeliveryCount() pulumi.IntOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) int { return v.DeadLetterQueueDeliveryCount }).(pulumi.IntOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o GetQueuesQueueCollectionItemOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// A filter to return only resources that match the entire display name given.
func (o GetQueuesQueueCollectionItemOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o GetQueuesQueueCollectionItemOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// unique Queue identifier
func (o GetQueuesQueueCollectionItemOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) string { return v.Id }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o GetQueuesQueueCollectionItemOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The endpoint to use to consume or publish messages in the queue.
func (o GetQueuesQueueCollectionItemOutput) MessagesEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) string { return v.MessagesEndpoint }).(pulumi.StringOutput)
}

func (o GetQueuesQueueCollectionItemOutput) PurgeQueue() pulumi.BoolOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) bool { return v.PurgeQueue }).(pulumi.BoolOutput)
}

func (o GetQueuesQueueCollectionItemOutput) PurgeType() pulumi.StringOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) string { return v.PurgeType }).(pulumi.StringOutput)
}

// The retention period of the messages in the queue, in seconds.
func (o GetQueuesQueueCollectionItemOutput) RetentionInSeconds() pulumi.IntOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) int { return v.RetentionInSeconds }).(pulumi.IntOutput)
}

// A filter to return only resources their lifecycleState matches the given lifecycleState.
func (o GetQueuesQueueCollectionItemOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o GetQueuesQueueCollectionItemOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// The time the the Queue was created. An RFC3339 formatted datetime string
func (o GetQueuesQueueCollectionItemOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the Queue was updated. An RFC3339 formatted datetime string
func (o GetQueuesQueueCollectionItemOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The default polling timeout of the messages in the queue, in seconds.
func (o GetQueuesQueueCollectionItemOutput) TimeoutInSeconds() pulumi.IntOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) int { return v.TimeoutInSeconds }).(pulumi.IntOutput)
}

// The default visibility of the messages consumed from the queue.
func (o GetQueuesQueueCollectionItemOutput) VisibilityInSeconds() pulumi.IntOutput {
	return o.ApplyT(func(v GetQueuesQueueCollectionItem) int { return v.VisibilityInSeconds }).(pulumi.IntOutput)
}

type GetQueuesQueueCollectionItemArrayOutput struct{ *pulumi.OutputState }

func (GetQueuesQueueCollectionItemArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetQueuesQueueCollectionItem)(nil)).Elem()
}

func (o GetQueuesQueueCollectionItemArrayOutput) ToGetQueuesQueueCollectionItemArrayOutput() GetQueuesQueueCollectionItemArrayOutput {
	return o
}

func (o GetQueuesQueueCollectionItemArrayOutput) ToGetQueuesQueueCollectionItemArrayOutputWithContext(ctx context.Context) GetQueuesQueueCollectionItemArrayOutput {
	return o
}

func (o GetQueuesQueueCollectionItemArrayOutput) Index(i pulumi.IntInput) GetQueuesQueueCollectionItemOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) GetQueuesQueueCollectionItem {
		return vs[0].([]GetQueuesQueueCollectionItem)[vs[1].(int)]
	}).(GetQueuesQueueCollectionItemOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*GetQueuesFilterInput)(nil)).Elem(), GetQueuesFilterArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*GetQueuesFilterArrayInput)(nil)).Elem(), GetQueuesFilterArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*GetQueuesQueueCollectionInput)(nil)).Elem(), GetQueuesQueueCollectionArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*GetQueuesQueueCollectionArrayInput)(nil)).Elem(), GetQueuesQueueCollectionArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*GetQueuesQueueCollectionItemInput)(nil)).Elem(), GetQueuesQueueCollectionItemArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*GetQueuesQueueCollectionItemArrayInput)(nil)).Elem(), GetQueuesQueueCollectionItemArray{})
	pulumi.RegisterOutputType(GetQueuesFilterOutput{})
	pulumi.RegisterOutputType(GetQueuesFilterArrayOutput{})
	pulumi.RegisterOutputType(GetQueuesQueueCollectionOutput{})
	pulumi.RegisterOutputType(GetQueuesQueueCollectionArrayOutput{})
	pulumi.RegisterOutputType(GetQueuesQueueCollectionItemOutput{})
	pulumi.RegisterOutputType(GetQueuesQueueCollectionItemArrayOutput{})
}