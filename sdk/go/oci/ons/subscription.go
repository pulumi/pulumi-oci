// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package ons

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Subscription resource in Oracle Cloud Infrastructure Notifications service.
//
// Creates a subscription for the specified topic and sends a subscription confirmation URL to the endpoint. The subscription remains in "Pending" status until it has been confirmed.
// For information about confirming subscriptions, see
// [To confirm a subscription](https://docs.cloud.oracle.com/iaas/Content/Notification/Tasks/managingtopicsandsubscriptions.htm#confirmSub).
//
// Transactions Per Minute (TPM) per-tenancy limit for this operation: 60.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Ons"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Ons.NewSubscription(ctx, "testSubscription", &Ons.SubscriptionArgs{
//				CompartmentId: pulumi.Any(_var.Compartment_id),
//				Endpoint:      pulumi.Any(_var.Subscription_endpoint),
//				Protocol:      pulumi.Any(_var.Subscription_protocol),
//				TopicId:       pulumi.Any(oci_ons_notification_topic.Test_notification_topic.Id),
//				DefinedTags: pulumi.AnyMap{
//					"Operations.CostCenter": pulumi.Any("42"),
//				},
//				FreeformTags: pulumi.AnyMap{
//					"Department": pulumi.Any("Finance"),
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
// Subscriptions can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Ons/subscription:Subscription test_subscription "id"
//
// ```
type Subscription struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the subscription.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// The time when this suscription was created.
	CreatedTime pulumi.StringOutput `pulumi:"createdTime"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// The delivery policy of the subscription. Stored as a JSON string.
	DeliveryPolicy pulumi.StringOutput `pulumi:"deliveryPolicy"`
	// A locator that corresponds to the subscription protocol. For example, an email address for a subscription that uses the `EMAIL` protocol, or a URL for a subscription that uses an HTTP-based protocol. HTTP-based protocols use URL endpoints that begin with "http:" or "https:". A URL cannot exceed 512 characters. Avoid entering confidential information.
	Endpoint pulumi.StringOutput `pulumi:"endpoint"`
	// For optimistic concurrency control. See `if-match`.
	Etag pulumi.StringOutput `pulumi:"etag"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The protocol used for the subscription.
	Protocol pulumi.StringOutput `pulumi:"protocol"`
	// The lifecycle state of the subscription. The status of a new subscription is PENDING; when confirmed, the subscription status changes to ACTIVE.
	State pulumi.StringOutput `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic for the subscription.
	TopicId pulumi.StringOutput `pulumi:"topicId"`
}

// NewSubscription registers a new resource with the given unique name, arguments, and options.
func NewSubscription(ctx *pulumi.Context,
	name string, args *SubscriptionArgs, opts ...pulumi.ResourceOption) (*Subscription, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.Endpoint == nil {
		return nil, errors.New("invalid value for required argument 'Endpoint'")
	}
	if args.Protocol == nil {
		return nil, errors.New("invalid value for required argument 'Protocol'")
	}
	if args.TopicId == nil {
		return nil, errors.New("invalid value for required argument 'TopicId'")
	}
	var resource Subscription
	err := ctx.RegisterResource("oci:Ons/subscription:Subscription", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetSubscription gets an existing Subscription resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetSubscription(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *SubscriptionState, opts ...pulumi.ResourceOption) (*Subscription, error) {
	var resource Subscription
	err := ctx.ReadResource("oci:Ons/subscription:Subscription", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Subscription resources.
type subscriptionState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the subscription.
	CompartmentId *string `pulumi:"compartmentId"`
	// The time when this suscription was created.
	CreatedTime *string `pulumi:"createdTime"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The delivery policy of the subscription. Stored as a JSON string.
	DeliveryPolicy *string `pulumi:"deliveryPolicy"`
	// A locator that corresponds to the subscription protocol. For example, an email address for a subscription that uses the `EMAIL` protocol, or a URL for a subscription that uses an HTTP-based protocol. HTTP-based protocols use URL endpoints that begin with "http:" or "https:". A URL cannot exceed 512 characters. Avoid entering confidential information.
	Endpoint *string `pulumi:"endpoint"`
	// For optimistic concurrency control. See `if-match`.
	Etag *string `pulumi:"etag"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The protocol used for the subscription.
	Protocol *string `pulumi:"protocol"`
	// The lifecycle state of the subscription. The status of a new subscription is PENDING; when confirmed, the subscription status changes to ACTIVE.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic for the subscription.
	TopicId *string `pulumi:"topicId"`
}

type SubscriptionState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the subscription.
	CompartmentId pulumi.StringPtrInput
	// The time when this suscription was created.
	CreatedTime pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// The delivery policy of the subscription. Stored as a JSON string.
	DeliveryPolicy pulumi.StringPtrInput
	// A locator that corresponds to the subscription protocol. For example, an email address for a subscription that uses the `EMAIL` protocol, or a URL for a subscription that uses an HTTP-based protocol. HTTP-based protocols use URL endpoints that begin with "http:" or "https:". A URL cannot exceed 512 characters. Avoid entering confidential information.
	Endpoint pulumi.StringPtrInput
	// For optimistic concurrency control. See `if-match`.
	Etag pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The protocol used for the subscription.
	Protocol pulumi.StringPtrInput
	// The lifecycle state of the subscription. The status of a new subscription is PENDING; when confirmed, the subscription status changes to ACTIVE.
	State pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic for the subscription.
	TopicId pulumi.StringPtrInput
}

func (SubscriptionState) ElementType() reflect.Type {
	return reflect.TypeOf((*subscriptionState)(nil)).Elem()
}

type subscriptionArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the subscription.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The delivery policy of the subscription. Stored as a JSON string.
	DeliveryPolicy *string `pulumi:"deliveryPolicy"`
	// A locator that corresponds to the subscription protocol. For example, an email address for a subscription that uses the `EMAIL` protocol, or a URL for a subscription that uses an HTTP-based protocol. HTTP-based protocols use URL endpoints that begin with "http:" or "https:". A URL cannot exceed 512 characters. Avoid entering confidential information.
	Endpoint string `pulumi:"endpoint"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The protocol used for the subscription.
	Protocol string `pulumi:"protocol"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic for the subscription.
	TopicId string `pulumi:"topicId"`
}

// The set of arguments for constructing a Subscription resource.
type SubscriptionArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the subscription.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// The delivery policy of the subscription. Stored as a JSON string.
	DeliveryPolicy pulumi.StringPtrInput
	// A locator that corresponds to the subscription protocol. For example, an email address for a subscription that uses the `EMAIL` protocol, or a URL for a subscription that uses an HTTP-based protocol. HTTP-based protocols use URL endpoints that begin with "http:" or "https:". A URL cannot exceed 512 characters. Avoid entering confidential information.
	Endpoint pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The protocol used for the subscription.
	Protocol pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic for the subscription.
	TopicId pulumi.StringInput
}

func (SubscriptionArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*subscriptionArgs)(nil)).Elem()
}

type SubscriptionInput interface {
	pulumi.Input

	ToSubscriptionOutput() SubscriptionOutput
	ToSubscriptionOutputWithContext(ctx context.Context) SubscriptionOutput
}

func (*Subscription) ElementType() reflect.Type {
	return reflect.TypeOf((**Subscription)(nil)).Elem()
}

func (i *Subscription) ToSubscriptionOutput() SubscriptionOutput {
	return i.ToSubscriptionOutputWithContext(context.Background())
}

func (i *Subscription) ToSubscriptionOutputWithContext(ctx context.Context) SubscriptionOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SubscriptionOutput)
}

// SubscriptionArrayInput is an input type that accepts SubscriptionArray and SubscriptionArrayOutput values.
// You can construct a concrete instance of `SubscriptionArrayInput` via:
//
//	SubscriptionArray{ SubscriptionArgs{...} }
type SubscriptionArrayInput interface {
	pulumi.Input

	ToSubscriptionArrayOutput() SubscriptionArrayOutput
	ToSubscriptionArrayOutputWithContext(context.Context) SubscriptionArrayOutput
}

type SubscriptionArray []SubscriptionInput

func (SubscriptionArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Subscription)(nil)).Elem()
}

func (i SubscriptionArray) ToSubscriptionArrayOutput() SubscriptionArrayOutput {
	return i.ToSubscriptionArrayOutputWithContext(context.Background())
}

func (i SubscriptionArray) ToSubscriptionArrayOutputWithContext(ctx context.Context) SubscriptionArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SubscriptionArrayOutput)
}

// SubscriptionMapInput is an input type that accepts SubscriptionMap and SubscriptionMapOutput values.
// You can construct a concrete instance of `SubscriptionMapInput` via:
//
//	SubscriptionMap{ "key": SubscriptionArgs{...} }
type SubscriptionMapInput interface {
	pulumi.Input

	ToSubscriptionMapOutput() SubscriptionMapOutput
	ToSubscriptionMapOutputWithContext(context.Context) SubscriptionMapOutput
}

type SubscriptionMap map[string]SubscriptionInput

func (SubscriptionMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Subscription)(nil)).Elem()
}

func (i SubscriptionMap) ToSubscriptionMapOutput() SubscriptionMapOutput {
	return i.ToSubscriptionMapOutputWithContext(context.Background())
}

func (i SubscriptionMap) ToSubscriptionMapOutputWithContext(ctx context.Context) SubscriptionMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SubscriptionMapOutput)
}

type SubscriptionOutput struct{ *pulumi.OutputState }

func (SubscriptionOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Subscription)(nil)).Elem()
}

func (o SubscriptionOutput) ToSubscriptionOutput() SubscriptionOutput {
	return o
}

func (o SubscriptionOutput) ToSubscriptionOutputWithContext(ctx context.Context) SubscriptionOutput {
	return o
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the subscription.
func (o SubscriptionOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Subscription) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// The time when this suscription was created.
func (o SubscriptionOutput) CreatedTime() pulumi.StringOutput {
	return o.ApplyT(func(v *Subscription) pulumi.StringOutput { return v.CreatedTime }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o SubscriptionOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Subscription) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// The delivery policy of the subscription. Stored as a JSON string.
func (o SubscriptionOutput) DeliveryPolicy() pulumi.StringOutput {
	return o.ApplyT(func(v *Subscription) pulumi.StringOutput { return v.DeliveryPolicy }).(pulumi.StringOutput)
}

// A locator that corresponds to the subscription protocol. For example, an email address for a subscription that uses the `EMAIL` protocol, or a URL for a subscription that uses an HTTP-based protocol. HTTP-based protocols use URL endpoints that begin with "http:" or "https:". A URL cannot exceed 512 characters. Avoid entering confidential information.
func (o SubscriptionOutput) Endpoint() pulumi.StringOutput {
	return o.ApplyT(func(v *Subscription) pulumi.StringOutput { return v.Endpoint }).(pulumi.StringOutput)
}

// For optimistic concurrency control. See `if-match`.
func (o SubscriptionOutput) Etag() pulumi.StringOutput {
	return o.ApplyT(func(v *Subscription) pulumi.StringOutput { return v.Etag }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o SubscriptionOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Subscription) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// The protocol used for the subscription.
func (o SubscriptionOutput) Protocol() pulumi.StringOutput {
	return o.ApplyT(func(v *Subscription) pulumi.StringOutput { return v.Protocol }).(pulumi.StringOutput)
}

// The lifecycle state of the subscription. The status of a new subscription is PENDING; when confirmed, the subscription status changes to ACTIVE.
func (o SubscriptionOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Subscription) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic for the subscription.
func (o SubscriptionOutput) TopicId() pulumi.StringOutput {
	return o.ApplyT(func(v *Subscription) pulumi.StringOutput { return v.TopicId }).(pulumi.StringOutput)
}

type SubscriptionArrayOutput struct{ *pulumi.OutputState }

func (SubscriptionArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Subscription)(nil)).Elem()
}

func (o SubscriptionArrayOutput) ToSubscriptionArrayOutput() SubscriptionArrayOutput {
	return o
}

func (o SubscriptionArrayOutput) ToSubscriptionArrayOutputWithContext(ctx context.Context) SubscriptionArrayOutput {
	return o
}

func (o SubscriptionArrayOutput) Index(i pulumi.IntInput) SubscriptionOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Subscription {
		return vs[0].([]*Subscription)[vs[1].(int)]
	}).(SubscriptionOutput)
}

type SubscriptionMapOutput struct{ *pulumi.OutputState }

func (SubscriptionMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Subscription)(nil)).Elem()
}

func (o SubscriptionMapOutput) ToSubscriptionMapOutput() SubscriptionMapOutput {
	return o
}

func (o SubscriptionMapOutput) ToSubscriptionMapOutputWithContext(ctx context.Context) SubscriptionMapOutput {
	return o
}

func (o SubscriptionMapOutput) MapIndex(k pulumi.StringInput) SubscriptionOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Subscription {
		return vs[0].(map[string]*Subscription)[vs[1].(string)]
	}).(SubscriptionOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*SubscriptionInput)(nil)).Elem(), &Subscription{})
	pulumi.RegisterInputType(reflect.TypeOf((*SubscriptionArrayInput)(nil)).Elem(), SubscriptionArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*SubscriptionMapInput)(nil)).Elem(), SubscriptionMap{})
	pulumi.RegisterOutputType(SubscriptionOutput{})
	pulumi.RegisterOutputType(SubscriptionArrayOutput{})
	pulumi.RegisterOutputType(SubscriptionMapOutput{})
}