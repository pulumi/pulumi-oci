// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package streaming

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Stream Pool resource in Oracle Cloud Infrastructure Streaming service.
//
// Starts the provisioning of a new stream pool.
// To track the progress of the provisioning, you can periodically call GetStreamPool.
// In the response, the `lifecycleState` parameter of the object tells you its current state.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Streaming"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Streaming.NewStreamPool(ctx, "testStreamPool", &Streaming.StreamPoolArgs{
//				CompartmentId: pulumi.Any(_var.Compartment_id),
//				CustomEncryptionKey: &streaming.StreamPoolCustomEncryptionKeyArgs{
//					KmsKeyId: pulumi.Any(oci_kms_key.Test_key.Id),
//				},
//				DefinedTags: pulumi.Any(_var.Stream_pool_defined_tags),
//				FreeformTags: pulumi.AnyMap{
//					"Department": pulumi.Any("Finance"),
//				},
//				KafkaSettings: &streaming.StreamPoolKafkaSettingsArgs{
//					AutoCreateTopicsEnable: pulumi.Any(_var.Stream_pool_kafka_settings_auto_create_topics_enable),
//					BootstrapServers:       pulumi.Any(_var.Stream_pool_kafka_settings_bootstrap_servers),
//					LogRetentionHours:      pulumi.Any(_var.Stream_pool_kafka_settings_log_retention_hours),
//					NumPartitions:          pulumi.Any(_var.Stream_pool_kafka_settings_num_partitions),
//				},
//				PrivateEndpointSettings: &streaming.StreamPoolPrivateEndpointSettingsArgs{
//					NsgIds:            pulumi.Any(_var.Stream_pool_private_endpoint_settings_nsg_ids),
//					PrivateEndpointIp: pulumi.Any(_var.Stream_pool_private_endpoint_settings_private_endpoint_ip),
//					SubnetId:          pulumi.Any(oci_core_subnet.Test_subnet.Id),
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
// StreamPools can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Streaming/streamPool:StreamPool test_stream_pool "id"
//
// ```
type StreamPool struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment that contains the stream.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The OCID of the custom encryption key to be used or deleted if currently being used.
	CustomEncryptionKey StreamPoolCustomEncryptionKeyOutput `pulumi:"customEncryptionKey"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// The FQDN used to access the streams inside the stream pool (same FQDN as the messagesEndpoint attribute of a [Stream](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/Stream) object). If the stream pool is private, the FQDN is customized and can only be accessed from inside the associated subnetId, otherwise the FQDN is publicly resolvable. Depending on which protocol you attempt to use, you need to either prepend https or append the Kafka port.
	EndpointFqdn pulumi.StringOutput `pulumi:"endpointFqdn"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// True if the stream pool is private, false otherwise. The associated endpoint and subnetId of a private stream pool can be retrieved through the [GetStreamPool](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/StreamPool/GetStreamPool) API.
	IsPrivate pulumi.BoolOutput `pulumi:"isPrivate"`
	// (Updatable) Settings for the Kafka compatibility layer.
	KafkaSettings StreamPoolKafkaSettingsOutput `pulumi:"kafkaSettings"`
	// Any additional details about the current state of the stream.
	LifecycleStateDetails pulumi.StringOutput `pulumi:"lifecycleStateDetails"`
	// (Updatable) The name of the stream pool. Avoid entering confidential information.  Example: `MyStreamPool`
	Name pulumi.StringOutput `pulumi:"name"`
	// Optional parameters if a private stream pool is requested.
	PrivateEndpointSettings StreamPoolPrivateEndpointSettingsOutput `pulumi:"privateEndpointSettings"`
	// The current state of the stream pool.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the stream pool was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewStreamPool registers a new resource with the given unique name, arguments, and options.
func NewStreamPool(ctx *pulumi.Context,
	name string, args *StreamPoolArgs, opts ...pulumi.ResourceOption) (*StreamPool, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	var resource StreamPool
	err := ctx.RegisterResource("oci:Streaming/streamPool:StreamPool", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetStreamPool gets an existing StreamPool resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetStreamPool(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *StreamPoolState, opts ...pulumi.ResourceOption) (*StreamPool, error) {
	var resource StreamPool
	err := ctx.ReadResource("oci:Streaming/streamPool:StreamPool", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering StreamPool resources.
type streamPoolState struct {
	// (Updatable) The OCID of the compartment that contains the stream.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The OCID of the custom encryption key to be used or deleted if currently being used.
	CustomEncryptionKey *StreamPoolCustomEncryptionKey `pulumi:"customEncryptionKey"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The FQDN used to access the streams inside the stream pool (same FQDN as the messagesEndpoint attribute of a [Stream](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/Stream) object). If the stream pool is private, the FQDN is customized and can only be accessed from inside the associated subnetId, otherwise the FQDN is publicly resolvable. Depending on which protocol you attempt to use, you need to either prepend https or append the Kafka port.
	EndpointFqdn *string `pulumi:"endpointFqdn"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// True if the stream pool is private, false otherwise. The associated endpoint and subnetId of a private stream pool can be retrieved through the [GetStreamPool](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/StreamPool/GetStreamPool) API.
	IsPrivate *bool `pulumi:"isPrivate"`
	// (Updatable) Settings for the Kafka compatibility layer.
	KafkaSettings *StreamPoolKafkaSettings `pulumi:"kafkaSettings"`
	// Any additional details about the current state of the stream.
	LifecycleStateDetails *string `pulumi:"lifecycleStateDetails"`
	// (Updatable) The name of the stream pool. Avoid entering confidential information.  Example: `MyStreamPool`
	Name *string `pulumi:"name"`
	// Optional parameters if a private stream pool is requested.
	PrivateEndpointSettings *StreamPoolPrivateEndpointSettings `pulumi:"privateEndpointSettings"`
	// The current state of the stream pool.
	State *string `pulumi:"state"`
	// The date and time the stream pool was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type StreamPoolState struct {
	// (Updatable) The OCID of the compartment that contains the stream.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The OCID of the custom encryption key to be used or deleted if currently being used.
	CustomEncryptionKey StreamPoolCustomEncryptionKeyPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// The FQDN used to access the streams inside the stream pool (same FQDN as the messagesEndpoint attribute of a [Stream](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/Stream) object). If the stream pool is private, the FQDN is customized and can only be accessed from inside the associated subnetId, otherwise the FQDN is publicly resolvable. Depending on which protocol you attempt to use, you need to either prepend https or append the Kafka port.
	EndpointFqdn pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// True if the stream pool is private, false otherwise. The associated endpoint and subnetId of a private stream pool can be retrieved through the [GetStreamPool](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/StreamPool/GetStreamPool) API.
	IsPrivate pulumi.BoolPtrInput
	// (Updatable) Settings for the Kafka compatibility layer.
	KafkaSettings StreamPoolKafkaSettingsPtrInput
	// Any additional details about the current state of the stream.
	LifecycleStateDetails pulumi.StringPtrInput
	// (Updatable) The name of the stream pool. Avoid entering confidential information.  Example: `MyStreamPool`
	Name pulumi.StringPtrInput
	// Optional parameters if a private stream pool is requested.
	PrivateEndpointSettings StreamPoolPrivateEndpointSettingsPtrInput
	// The current state of the stream pool.
	State pulumi.StringPtrInput
	// The date and time the stream pool was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
	TimeCreated pulumi.StringPtrInput
}

func (StreamPoolState) ElementType() reflect.Type {
	return reflect.TypeOf((*streamPoolState)(nil)).Elem()
}

type streamPoolArgs struct {
	// (Updatable) The OCID of the compartment that contains the stream.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) The OCID of the custom encryption key to be used or deleted if currently being used.
	CustomEncryptionKey *StreamPoolCustomEncryptionKey `pulumi:"customEncryptionKey"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Settings for the Kafka compatibility layer.
	KafkaSettings *StreamPoolKafkaSettings `pulumi:"kafkaSettings"`
	// (Updatable) The name of the stream pool. Avoid entering confidential information.  Example: `MyStreamPool`
	Name *string `pulumi:"name"`
	// Optional parameters if a private stream pool is requested.
	PrivateEndpointSettings *StreamPoolPrivateEndpointSettings `pulumi:"privateEndpointSettings"`
}

// The set of arguments for constructing a StreamPool resource.
type StreamPoolArgs struct {
	// (Updatable) The OCID of the compartment that contains the stream.
	CompartmentId pulumi.StringInput
	// (Updatable) The OCID of the custom encryption key to be used or deleted if currently being used.
	CustomEncryptionKey StreamPoolCustomEncryptionKeyPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Settings for the Kafka compatibility layer.
	KafkaSettings StreamPoolKafkaSettingsPtrInput
	// (Updatable) The name of the stream pool. Avoid entering confidential information.  Example: `MyStreamPool`
	Name pulumi.StringPtrInput
	// Optional parameters if a private stream pool is requested.
	PrivateEndpointSettings StreamPoolPrivateEndpointSettingsPtrInput
}

func (StreamPoolArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*streamPoolArgs)(nil)).Elem()
}

type StreamPoolInput interface {
	pulumi.Input

	ToStreamPoolOutput() StreamPoolOutput
	ToStreamPoolOutputWithContext(ctx context.Context) StreamPoolOutput
}

func (*StreamPool) ElementType() reflect.Type {
	return reflect.TypeOf((**StreamPool)(nil)).Elem()
}

func (i *StreamPool) ToStreamPoolOutput() StreamPoolOutput {
	return i.ToStreamPoolOutputWithContext(context.Background())
}

func (i *StreamPool) ToStreamPoolOutputWithContext(ctx context.Context) StreamPoolOutput {
	return pulumi.ToOutputWithContext(ctx, i).(StreamPoolOutput)
}

// StreamPoolArrayInput is an input type that accepts StreamPoolArray and StreamPoolArrayOutput values.
// You can construct a concrete instance of `StreamPoolArrayInput` via:
//
//	StreamPoolArray{ StreamPoolArgs{...} }
type StreamPoolArrayInput interface {
	pulumi.Input

	ToStreamPoolArrayOutput() StreamPoolArrayOutput
	ToStreamPoolArrayOutputWithContext(context.Context) StreamPoolArrayOutput
}

type StreamPoolArray []StreamPoolInput

func (StreamPoolArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*StreamPool)(nil)).Elem()
}

func (i StreamPoolArray) ToStreamPoolArrayOutput() StreamPoolArrayOutput {
	return i.ToStreamPoolArrayOutputWithContext(context.Background())
}

func (i StreamPoolArray) ToStreamPoolArrayOutputWithContext(ctx context.Context) StreamPoolArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(StreamPoolArrayOutput)
}

// StreamPoolMapInput is an input type that accepts StreamPoolMap and StreamPoolMapOutput values.
// You can construct a concrete instance of `StreamPoolMapInput` via:
//
//	StreamPoolMap{ "key": StreamPoolArgs{...} }
type StreamPoolMapInput interface {
	pulumi.Input

	ToStreamPoolMapOutput() StreamPoolMapOutput
	ToStreamPoolMapOutputWithContext(context.Context) StreamPoolMapOutput
}

type StreamPoolMap map[string]StreamPoolInput

func (StreamPoolMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*StreamPool)(nil)).Elem()
}

func (i StreamPoolMap) ToStreamPoolMapOutput() StreamPoolMapOutput {
	return i.ToStreamPoolMapOutputWithContext(context.Background())
}

func (i StreamPoolMap) ToStreamPoolMapOutputWithContext(ctx context.Context) StreamPoolMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(StreamPoolMapOutput)
}

type StreamPoolOutput struct{ *pulumi.OutputState }

func (StreamPoolOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**StreamPool)(nil)).Elem()
}

func (o StreamPoolOutput) ToStreamPoolOutput() StreamPoolOutput {
	return o
}

func (o StreamPoolOutput) ToStreamPoolOutputWithContext(ctx context.Context) StreamPoolOutput {
	return o
}

// (Updatable) The OCID of the compartment that contains the stream.
func (o StreamPoolOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *StreamPool) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) The OCID of the custom encryption key to be used or deleted if currently being used.
func (o StreamPoolOutput) CustomEncryptionKey() StreamPoolCustomEncryptionKeyOutput {
	return o.ApplyT(func(v *StreamPool) StreamPoolCustomEncryptionKeyOutput { return v.CustomEncryptionKey }).(StreamPoolCustomEncryptionKeyOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o StreamPoolOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *StreamPool) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// The FQDN used to access the streams inside the stream pool (same FQDN as the messagesEndpoint attribute of a [Stream](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/Stream) object). If the stream pool is private, the FQDN is customized and can only be accessed from inside the associated subnetId, otherwise the FQDN is publicly resolvable. Depending on which protocol you attempt to use, you need to either prepend https or append the Kafka port.
func (o StreamPoolOutput) EndpointFqdn() pulumi.StringOutput {
	return o.ApplyT(func(v *StreamPool) pulumi.StringOutput { return v.EndpointFqdn }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o StreamPoolOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *StreamPool) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// True if the stream pool is private, false otherwise. The associated endpoint and subnetId of a private stream pool can be retrieved through the [GetStreamPool](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/StreamPool/GetStreamPool) API.
func (o StreamPoolOutput) IsPrivate() pulumi.BoolOutput {
	return o.ApplyT(func(v *StreamPool) pulumi.BoolOutput { return v.IsPrivate }).(pulumi.BoolOutput)
}

// (Updatable) Settings for the Kafka compatibility layer.
func (o StreamPoolOutput) KafkaSettings() StreamPoolKafkaSettingsOutput {
	return o.ApplyT(func(v *StreamPool) StreamPoolKafkaSettingsOutput { return v.KafkaSettings }).(StreamPoolKafkaSettingsOutput)
}

// Any additional details about the current state of the stream.
func (o StreamPoolOutput) LifecycleStateDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *StreamPool) pulumi.StringOutput { return v.LifecycleStateDetails }).(pulumi.StringOutput)
}

// (Updatable) The name of the stream pool. Avoid entering confidential information.  Example: `MyStreamPool`
func (o StreamPoolOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *StreamPool) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// Optional parameters if a private stream pool is requested.
func (o StreamPoolOutput) PrivateEndpointSettings() StreamPoolPrivateEndpointSettingsOutput {
	return o.ApplyT(func(v *StreamPool) StreamPoolPrivateEndpointSettingsOutput { return v.PrivateEndpointSettings }).(StreamPoolPrivateEndpointSettingsOutput)
}

// The current state of the stream pool.
func (o StreamPoolOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *StreamPool) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the stream pool was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
func (o StreamPoolOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *StreamPool) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

type StreamPoolArrayOutput struct{ *pulumi.OutputState }

func (StreamPoolArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*StreamPool)(nil)).Elem()
}

func (o StreamPoolArrayOutput) ToStreamPoolArrayOutput() StreamPoolArrayOutput {
	return o
}

func (o StreamPoolArrayOutput) ToStreamPoolArrayOutputWithContext(ctx context.Context) StreamPoolArrayOutput {
	return o
}

func (o StreamPoolArrayOutput) Index(i pulumi.IntInput) StreamPoolOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *StreamPool {
		return vs[0].([]*StreamPool)[vs[1].(int)]
	}).(StreamPoolOutput)
}

type StreamPoolMapOutput struct{ *pulumi.OutputState }

func (StreamPoolMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*StreamPool)(nil)).Elem()
}

func (o StreamPoolMapOutput) ToStreamPoolMapOutput() StreamPoolMapOutput {
	return o
}

func (o StreamPoolMapOutput) ToStreamPoolMapOutputWithContext(ctx context.Context) StreamPoolMapOutput {
	return o
}

func (o StreamPoolMapOutput) MapIndex(k pulumi.StringInput) StreamPoolOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *StreamPool {
		return vs[0].(map[string]*StreamPool)[vs[1].(string)]
	}).(StreamPoolOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*StreamPoolInput)(nil)).Elem(), &StreamPool{})
	pulumi.RegisterInputType(reflect.TypeOf((*StreamPoolArrayInput)(nil)).Elem(), StreamPoolArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*StreamPoolMapInput)(nil)).Elem(), StreamPoolMap{})
	pulumi.RegisterOutputType(StreamPoolOutput{})
	pulumi.RegisterOutputType(StreamPoolArrayOutput{})
	pulumi.RegisterOutputType(StreamPoolMapOutput{})
}