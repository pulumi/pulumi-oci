// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package queue

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Queue resource in Oracle Cloud Infrastructure Queue service.
//
// Creates a new Queue.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Queue"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Queue.NewQueue(ctx, "testQueue", &Queue.QueueArgs{
//				CompartmentId:                pulumi.Any(_var.Compartment_id),
//				DisplayName:                  pulumi.Any(_var.Queue_display_name),
//				CustomEncryptionKeyId:        pulumi.Any(oci_kms_key.Test_key.Id),
//				DeadLetterQueueDeliveryCount: pulumi.Any(_var.Queue_dead_letter_queue_delivery_count),
//				DefinedTags: pulumi.AnyMap{
//					"foo-namespace.bar-key": pulumi.Any("value"),
//				},
//				FreeformTags: pulumi.AnyMap{
//					"bar-key": pulumi.Any("value"),
//				},
//				RetentionInSeconds:  pulumi.Any(_var.Queue_retention_in_seconds),
//				TimeoutInSeconds:    pulumi.Any(_var.Queue_timeout_in_seconds),
//				VisibilityInSeconds: pulumi.Any(_var.Queue_visibility_in_seconds),
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
// Queues can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Queue/queue:Queue test_queue "id"
//
// ```
type Queue struct {
	pulumi.CustomResourceState

	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Id of the custom master encryption key which will be used to encrypt messages content
	CustomEncryptionKeyId pulumi.StringOutput `pulumi:"customEncryptionKeyId"`
	// (Updatable) The number of times a message can be delivered to a consumer before being moved to the dead letter queue. A value of 0 indicates that the DLQ is not used.
	DeadLetterQueueDeliveryCount pulumi.IntOutput `pulumi:"deadLetterQueueDeliveryCount"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Queue Identifier
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The endpoint to use to consume or publish messages in the queue.
	MessagesEndpoint pulumi.StringOutput    `pulumi:"messagesEndpoint"`
	PurgeQueue       pulumi.BoolPtrOutput   `pulumi:"purgeQueue"`
	PurgeType        pulumi.StringPtrOutput `pulumi:"purgeType"`
	// The retention period of the messages in the queue, in seconds.
	RetentionInSeconds pulumi.IntOutput `pulumi:"retentionInSeconds"`
	// The current state of the Queue.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The time the the Queue was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the Queue was updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// (Updatable) The default polling timeout of the messages in the queue, in seconds.
	TimeoutInSeconds pulumi.IntOutput `pulumi:"timeoutInSeconds"`
	// (Updatable) The default visibility of the messages consumed from the queue.
	VisibilityInSeconds pulumi.IntOutput `pulumi:"visibilityInSeconds"`
}

// NewQueue registers a new resource with the given unique name, arguments, and options.
func NewQueue(ctx *pulumi.Context,
	name string, args *QueueArgs, opts ...pulumi.ResourceOption) (*Queue, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	var resource Queue
	err := ctx.RegisterResource("oci:Queue/queue:Queue", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetQueue gets an existing Queue resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetQueue(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *QueueState, opts ...pulumi.ResourceOption) (*Queue, error) {
	var resource Queue
	err := ctx.ReadResource("oci:Queue/queue:Queue", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Queue resources.
type queueState struct {
	// (Updatable) Compartment Identifier
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Id of the custom master encryption key which will be used to encrypt messages content
	CustomEncryptionKeyId *string `pulumi:"customEncryptionKeyId"`
	// (Updatable) The number of times a message can be delivered to a consumer before being moved to the dead letter queue. A value of 0 indicates that the DLQ is not used.
	DeadLetterQueueDeliveryCount *int `pulumi:"deadLetterQueueDeliveryCount"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Queue Identifier
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The endpoint to use to consume or publish messages in the queue.
	MessagesEndpoint *string `pulumi:"messagesEndpoint"`
	PurgeQueue       *bool   `pulumi:"purgeQueue"`
	PurgeType        *string `pulumi:"purgeType"`
	// The retention period of the messages in the queue, in seconds.
	RetentionInSeconds *int `pulumi:"retentionInSeconds"`
	// The current state of the Queue.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The time the the Queue was created. An RFC3339 formatted datetime string
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the Queue was updated. An RFC3339 formatted datetime string
	TimeUpdated *string `pulumi:"timeUpdated"`
	// (Updatable) The default polling timeout of the messages in the queue, in seconds.
	TimeoutInSeconds *int `pulumi:"timeoutInSeconds"`
	// (Updatable) The default visibility of the messages consumed from the queue.
	VisibilityInSeconds *int `pulumi:"visibilityInSeconds"`
}

type QueueState struct {
	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Id of the custom master encryption key which will be used to encrypt messages content
	CustomEncryptionKeyId pulumi.StringPtrInput
	// (Updatable) The number of times a message can be delivered to a consumer before being moved to the dead letter queue. A value of 0 indicates that the DLQ is not used.
	DeadLetterQueueDeliveryCount pulumi.IntPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Queue Identifier
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// The endpoint to use to consume or publish messages in the queue.
	MessagesEndpoint pulumi.StringPtrInput
	PurgeQueue       pulumi.BoolPtrInput
	PurgeType        pulumi.StringPtrInput
	// The retention period of the messages in the queue, in seconds.
	RetentionInSeconds pulumi.IntPtrInput
	// The current state of the Queue.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// The time the the Queue was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringPtrInput
	// The time the Queue was updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringPtrInput
	// (Updatable) The default polling timeout of the messages in the queue, in seconds.
	TimeoutInSeconds pulumi.IntPtrInput
	// (Updatable) The default visibility of the messages consumed from the queue.
	VisibilityInSeconds pulumi.IntPtrInput
}

func (QueueState) ElementType() reflect.Type {
	return reflect.TypeOf((*queueState)(nil)).Elem()
}

type queueArgs struct {
	// (Updatable) Compartment Identifier
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Id of the custom master encryption key which will be used to encrypt messages content
	CustomEncryptionKeyId *string `pulumi:"customEncryptionKeyId"`
	// (Updatable) The number of times a message can be delivered to a consumer before being moved to the dead letter queue. A value of 0 indicates that the DLQ is not used.
	DeadLetterQueueDeliveryCount *int `pulumi:"deadLetterQueueDeliveryCount"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Queue Identifier
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	PurgeQueue   *bool                  `pulumi:"purgeQueue"`
	PurgeType    *string                `pulumi:"purgeType"`
	// The retention period of the messages in the queue, in seconds.
	RetentionInSeconds *int `pulumi:"retentionInSeconds"`
	// (Updatable) The default polling timeout of the messages in the queue, in seconds.
	TimeoutInSeconds *int `pulumi:"timeoutInSeconds"`
	// (Updatable) The default visibility of the messages consumed from the queue.
	VisibilityInSeconds *int `pulumi:"visibilityInSeconds"`
}

// The set of arguments for constructing a Queue resource.
type QueueArgs struct {
	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringInput
	// (Updatable) Id of the custom master encryption key which will be used to encrypt messages content
	CustomEncryptionKeyId pulumi.StringPtrInput
	// (Updatable) The number of times a message can be delivered to a consumer before being moved to the dead letter queue. A value of 0 indicates that the DLQ is not used.
	DeadLetterQueueDeliveryCount pulumi.IntPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Queue Identifier
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	PurgeQueue   pulumi.BoolPtrInput
	PurgeType    pulumi.StringPtrInput
	// The retention period of the messages in the queue, in seconds.
	RetentionInSeconds pulumi.IntPtrInput
	// (Updatable) The default polling timeout of the messages in the queue, in seconds.
	TimeoutInSeconds pulumi.IntPtrInput
	// (Updatable) The default visibility of the messages consumed from the queue.
	VisibilityInSeconds pulumi.IntPtrInput
}

func (QueueArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*queueArgs)(nil)).Elem()
}

type QueueInput interface {
	pulumi.Input

	ToQueueOutput() QueueOutput
	ToQueueOutputWithContext(ctx context.Context) QueueOutput
}

func (*Queue) ElementType() reflect.Type {
	return reflect.TypeOf((**Queue)(nil)).Elem()
}

func (i *Queue) ToQueueOutput() QueueOutput {
	return i.ToQueueOutputWithContext(context.Background())
}

func (i *Queue) ToQueueOutputWithContext(ctx context.Context) QueueOutput {
	return pulumi.ToOutputWithContext(ctx, i).(QueueOutput)
}

// QueueArrayInput is an input type that accepts QueueArray and QueueArrayOutput values.
// You can construct a concrete instance of `QueueArrayInput` via:
//
//	QueueArray{ QueueArgs{...} }
type QueueArrayInput interface {
	pulumi.Input

	ToQueueArrayOutput() QueueArrayOutput
	ToQueueArrayOutputWithContext(context.Context) QueueArrayOutput
}

type QueueArray []QueueInput

func (QueueArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Queue)(nil)).Elem()
}

func (i QueueArray) ToQueueArrayOutput() QueueArrayOutput {
	return i.ToQueueArrayOutputWithContext(context.Background())
}

func (i QueueArray) ToQueueArrayOutputWithContext(ctx context.Context) QueueArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(QueueArrayOutput)
}

// QueueMapInput is an input type that accepts QueueMap and QueueMapOutput values.
// You can construct a concrete instance of `QueueMapInput` via:
//
//	QueueMap{ "key": QueueArgs{...} }
type QueueMapInput interface {
	pulumi.Input

	ToQueueMapOutput() QueueMapOutput
	ToQueueMapOutputWithContext(context.Context) QueueMapOutput
}

type QueueMap map[string]QueueInput

func (QueueMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Queue)(nil)).Elem()
}

func (i QueueMap) ToQueueMapOutput() QueueMapOutput {
	return i.ToQueueMapOutputWithContext(context.Background())
}

func (i QueueMap) ToQueueMapOutputWithContext(ctx context.Context) QueueMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(QueueMapOutput)
}

type QueueOutput struct{ *pulumi.OutputState }

func (QueueOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Queue)(nil)).Elem()
}

func (o QueueOutput) ToQueueOutput() QueueOutput {
	return o
}

func (o QueueOutput) ToQueueOutputWithContext(ctx context.Context) QueueOutput {
	return o
}

// (Updatable) Compartment Identifier
func (o QueueOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Queue) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Id of the custom master encryption key which will be used to encrypt messages content
func (o QueueOutput) CustomEncryptionKeyId() pulumi.StringOutput {
	return o.ApplyT(func(v *Queue) pulumi.StringOutput { return v.CustomEncryptionKeyId }).(pulumi.StringOutput)
}

// (Updatable) The number of times a message can be delivered to a consumer before being moved to the dead letter queue. A value of 0 indicates that the DLQ is not used.
func (o QueueOutput) DeadLetterQueueDeliveryCount() pulumi.IntOutput {
	return o.ApplyT(func(v *Queue) pulumi.IntOutput { return v.DeadLetterQueueDeliveryCount }).(pulumi.IntOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o QueueOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Queue) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) Queue Identifier
func (o QueueOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Queue) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o QueueOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Queue) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o QueueOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Queue) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The endpoint to use to consume or publish messages in the queue.
func (o QueueOutput) MessagesEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v *Queue) pulumi.StringOutput { return v.MessagesEndpoint }).(pulumi.StringOutput)
}

func (o QueueOutput) PurgeQueue() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v *Queue) pulumi.BoolPtrOutput { return v.PurgeQueue }).(pulumi.BoolPtrOutput)
}

func (o QueueOutput) PurgeType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *Queue) pulumi.StringPtrOutput { return v.PurgeType }).(pulumi.StringPtrOutput)
}

// The retention period of the messages in the queue, in seconds.
func (o QueueOutput) RetentionInSeconds() pulumi.IntOutput {
	return o.ApplyT(func(v *Queue) pulumi.IntOutput { return v.RetentionInSeconds }).(pulumi.IntOutput)
}

// The current state of the Queue.
func (o QueueOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Queue) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o QueueOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Queue) pulumi.MapOutput { return v.SystemTags }).(pulumi.MapOutput)
}

// The time the the Queue was created. An RFC3339 formatted datetime string
func (o QueueOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Queue) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the Queue was updated. An RFC3339 formatted datetime string
func (o QueueOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *Queue) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// (Updatable) The default polling timeout of the messages in the queue, in seconds.
func (o QueueOutput) TimeoutInSeconds() pulumi.IntOutput {
	return o.ApplyT(func(v *Queue) pulumi.IntOutput { return v.TimeoutInSeconds }).(pulumi.IntOutput)
}

// (Updatable) The default visibility of the messages consumed from the queue.
func (o QueueOutput) VisibilityInSeconds() pulumi.IntOutput {
	return o.ApplyT(func(v *Queue) pulumi.IntOutput { return v.VisibilityInSeconds }).(pulumi.IntOutput)
}

type QueueArrayOutput struct{ *pulumi.OutputState }

func (QueueArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Queue)(nil)).Elem()
}

func (o QueueArrayOutput) ToQueueArrayOutput() QueueArrayOutput {
	return o
}

func (o QueueArrayOutput) ToQueueArrayOutputWithContext(ctx context.Context) QueueArrayOutput {
	return o
}

func (o QueueArrayOutput) Index(i pulumi.IntInput) QueueOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Queue {
		return vs[0].([]*Queue)[vs[1].(int)]
	}).(QueueOutput)
}

type QueueMapOutput struct{ *pulumi.OutputState }

func (QueueMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Queue)(nil)).Elem()
}

func (o QueueMapOutput) ToQueueMapOutput() QueueMapOutput {
	return o
}

func (o QueueMapOutput) ToQueueMapOutputWithContext(ctx context.Context) QueueMapOutput {
	return o
}

func (o QueueMapOutput) MapIndex(k pulumi.StringInput) QueueOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Queue {
		return vs[0].(map[string]*Queue)[vs[1].(string)]
	}).(QueueOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*QueueInput)(nil)).Elem(), &Queue{})
	pulumi.RegisterInputType(reflect.TypeOf((*QueueArrayInput)(nil)).Elem(), QueueArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*QueueMapInput)(nil)).Elem(), QueueMap{})
	pulumi.RegisterOutputType(QueueOutput{})
	pulumi.RegisterOutputType(QueueArrayOutput{})
	pulumi.RegisterOutputType(QueueMapOutput{})
}