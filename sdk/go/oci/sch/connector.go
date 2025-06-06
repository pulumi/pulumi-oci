// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package sch

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Service Connector resource in Oracle Cloud Infrastructure Service Connector Hub service.
//
// Creates a new connector in the specified compartment.
// A connector is a logically defined flow for moving data from
// a source service to a destination service in Oracle Cloud Infrastructure.
// For more information, see
// [Creating a Connector](https://docs.cloud.oracle.com/iaas/Content/connector-hub/create-service-connector.htm).
// For general information about connectors, see
// [Overview of Connector Hub](https://docs.cloud.oracle.com/iaas/Content/connector-hub/overview.htm).
//
// For purposes of access control, you must provide the
// [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where
// you want the connector to reside. Notice that the connector
// doesn't have to be in the same compartment as the source or target services.
// For information about access control and compartments, see
// [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
//
// After you send your request, the new connector's state is temporarily
// CREATING. When the state changes to ACTIVE, data begins transferring from the
// source service to the target service. For instructions on deactivating and
// activating connectors, see
// [Activating a Connector](https://docs.cloud.oracle.com/iaas/Content/connector-hub/activate-service-connector.htm).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/sch"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := sch.NewConnector(ctx, "test_service_connector", &sch.ConnectorArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				DisplayName:   pulumi.Any(serviceConnectorDisplayName),
//				Source: &sch.ConnectorSourceArgs{
//					Kind:      pulumi.Any(serviceConnectorSourceKind),
//					ConfigMap: pulumi.Any(serviceConnectorSourceConfigMap),
//					Cursor: &sch.ConnectorSourceCursorArgs{
//						Kind: pulumi.Any(serviceConnectorSourceCursorKind),
//					},
//					LogSources: sch.ConnectorSourceLogSourceArray{
//						&sch.ConnectorSourceLogSourceArgs{
//							CompartmentId: pulumi.Any(compartmentId),
//							LogGroupId:    pulumi.Any(testLogGroup.Id),
//							LogId:         pulumi.Any(testLog.Id),
//						},
//					},
//					MonitoringSources: sch.ConnectorSourceMonitoringSourceArray{
//						&sch.ConnectorSourceMonitoringSourceArgs{
//							CompartmentId: pulumi.Any(compartmentId),
//							NamespaceDetails: &sch.ConnectorSourceMonitoringSourceNamespaceDetailsArgs{
//								Kind: pulumi.Any(serviceConnectorSourceMonitoringSourcesNamespaceDetailsKind),
//								Namespaces: sch.ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceArray{
//									&sch.ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceArgs{
//										Metrics: &sch.ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetricsArgs{
//											Kind: pulumi.Any(serviceConnectorSourceMonitoringSourcesNamespaceDetailsNamespacesMetricsKind),
//										},
//										Namespace: pulumi.Any(serviceConnectorSourceMonitoringSourcesNamespaceDetailsNamespacesNamespace),
//									},
//								},
//							},
//						},
//					},
//					PluginName: pulumi.Any(serviceConnectorSourcePluginName),
//					StreamId:   pulumi.Any(testStream.Id),
//				},
//				Target: &sch.ConnectorTargetArgs{
//					Kind:                   pulumi.Any(serviceConnectorTargetKind),
//					BatchRolloverSizeInMbs: pulumi.Any(serviceConnectorTargetBatchRolloverSizeInMbs),
//					BatchRolloverTimeInMs:  pulumi.Any(serviceConnectorTargetBatchRolloverTimeInMs),
//					BatchSizeInKbs:         pulumi.Any(serviceConnectorTargetBatchSizeInKbs),
//					BatchSizeInNum:         pulumi.Any(serviceConnectorTargetBatchSizeInNum),
//					BatchTimeInSec:         pulumi.Any(serviceConnectorTargetBatchTimeInSec),
//					Bucket:                 pulumi.Any(serviceConnectorTargetBucket),
//					CompartmentId:          pulumi.Any(compartmentId),
//					Dimensions: sch.ConnectorTargetDimensionArray{
//						&sch.ConnectorTargetDimensionArgs{
//							DimensionValue: &sch.ConnectorTargetDimensionDimensionValueArgs{
//								Kind:  pulumi.Any(serviceConnectorTargetDimensionsDimensionValueKind),
//								Path:  pulumi.Any(serviceConnectorTargetDimensionsDimensionValuePath),
//								Value: pulumi.Any(serviceConnectorTargetDimensionsDimensionValueValue),
//							},
//							Name: pulumi.Any(serviceConnectorTargetDimensionsName),
//						},
//					},
//					EnableFormattedMessaging: pulumi.Any(serviceConnectorTargetEnableFormattedMessaging),
//					FunctionId:               pulumi.Any(testFunction.Id),
//					LogGroupId:               pulumi.Any(testLogGroup.Id),
//					LogSourceIdentifier:      pulumi.Any(serviceConnectorTargetLogSourceIdentifier),
//					Metric:                   pulumi.Any(serviceConnectorTargetMetric),
//					MetricNamespace:          pulumi.Any(serviceConnectorTargetMetricNamespace),
//					Namespace:                pulumi.Any(serviceConnectorTargetNamespace),
//					ObjectNamePrefix:         pulumi.Any(serviceConnectorTargetObjectNamePrefix),
//					StreamId:                 pulumi.Any(testStream.Id),
//					TopicId:                  pulumi.Any(testNotificationTopic.Id),
//				},
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				Description: pulumi.Any(serviceConnectorDescription),
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				Tasks: sch.ConnectorTaskArray{
//					&sch.ConnectorTaskArgs{
//						Kind:           pulumi.Any(serviceConnectorTasksKind),
//						BatchSizeInKbs: pulumi.Any(serviceConnectorTasksBatchSizeInKbs),
//						BatchTimeInSec: pulumi.Any(serviceConnectorTasksBatchTimeInSec),
//						Condition:      pulumi.Any(serviceConnectorTasksCondition),
//						FunctionId:     pulumi.Any(testFunction.Id),
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
// ServiceConnectors can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Sch/connector:Connector test_service_connector "id"
// ```
type Connector struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the comparment to create the connector in.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) The description of the resource. Avoid entering confidential information.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// *Please note this property is deprecated and will be removed on January 27, 2026. Use `lifecycleDetails` instead.* A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
	LifecyleDetails pulumi.StringOutput `pulumi:"lifecyleDetails"`
	// (Updatable)
	Source ConnectorSourceOutput `pulumi:"source"`
	// (Updatable) The target state for the service connector. Could be set to `ACTIVE` or `INACTIVE`.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	State pulumi.StringOutput `pulumi:"state"`
	// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// (Updatable)
	Target ConnectorTargetOutput `pulumi:"target"`
	// (Updatable) The list of tasks.
	Tasks ConnectorTaskArrayOutput `pulumi:"tasks"`
	// The date and time when the connector was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time when the connector was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewConnector registers a new resource with the given unique name, arguments, and options.
func NewConnector(ctx *pulumi.Context,
	name string, args *ConnectorArgs, opts ...pulumi.ResourceOption) (*Connector, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.Source == nil {
		return nil, errors.New("invalid value for required argument 'Source'")
	}
	if args.Target == nil {
		return nil, errors.New("invalid value for required argument 'Target'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Connector
	err := ctx.RegisterResource("oci:Sch/connector:Connector", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetConnector gets an existing Connector resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetConnector(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ConnectorState, opts ...pulumi.ResourceOption) (*Connector, error) {
	var resource Connector
	err := ctx.ReadResource("oci:Sch/connector:Connector", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Connector resources.
type connectorState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the comparment to create the connector in.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The description of the resource. Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// *Please note this property is deprecated and will be removed on January 27, 2026. Use `lifecycleDetails` instead.* A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
	LifecyleDetails *string `pulumi:"lifecyleDetails"`
	// (Updatable)
	Source *ConnectorSource `pulumi:"source"`
	// (Updatable) The target state for the service connector. Could be set to `ACTIVE` or `INACTIVE`.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	State *string `pulumi:"state"`
	// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// (Updatable)
	Target *ConnectorTarget `pulumi:"target"`
	// (Updatable) The list of tasks.
	Tasks []ConnectorTask `pulumi:"tasks"`
	// The date and time when the connector was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time when the connector was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type ConnectorState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the comparment to create the connector in.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The description of the resource. Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
	LifecycleDetails pulumi.StringPtrInput
	// *Please note this property is deprecated and will be removed on January 27, 2026. Use `lifecycleDetails` instead.* A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
	LifecyleDetails pulumi.StringPtrInput
	// (Updatable)
	Source ConnectorSourcePtrInput
	// (Updatable) The target state for the service connector. Could be set to `ACTIVE` or `INACTIVE`.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	State pulumi.StringPtrInput
	// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags pulumi.StringMapInput
	// (Updatable)
	Target ConnectorTargetPtrInput
	// (Updatable) The list of tasks.
	Tasks ConnectorTaskArrayInput
	// The date and time when the connector was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The date and time when the connector was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
	TimeUpdated pulumi.StringPtrInput
}

func (ConnectorState) ElementType() reflect.Type {
	return reflect.TypeOf((*connectorState)(nil)).Elem()
}

type connectorArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the comparment to create the connector in.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The description of the resource. Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable)
	Source ConnectorSource `pulumi:"source"`
	// (Updatable) The target state for the service connector. Could be set to `ACTIVE` or `INACTIVE`.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	State *string `pulumi:"state"`
	// (Updatable)
	Target ConnectorTarget `pulumi:"target"`
	// (Updatable) The list of tasks.
	Tasks []ConnectorTask `pulumi:"tasks"`
}

// The set of arguments for constructing a Connector resource.
type ConnectorArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the comparment to create the connector in.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The description of the resource. Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable)
	Source ConnectorSourceInput
	// (Updatable) The target state for the service connector. Could be set to `ACTIVE` or `INACTIVE`.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	State pulumi.StringPtrInput
	// (Updatable)
	Target ConnectorTargetInput
	// (Updatable) The list of tasks.
	Tasks ConnectorTaskArrayInput
}

func (ConnectorArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*connectorArgs)(nil)).Elem()
}

type ConnectorInput interface {
	pulumi.Input

	ToConnectorOutput() ConnectorOutput
	ToConnectorOutputWithContext(ctx context.Context) ConnectorOutput
}

func (*Connector) ElementType() reflect.Type {
	return reflect.TypeOf((**Connector)(nil)).Elem()
}

func (i *Connector) ToConnectorOutput() ConnectorOutput {
	return i.ToConnectorOutputWithContext(context.Background())
}

func (i *Connector) ToConnectorOutputWithContext(ctx context.Context) ConnectorOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ConnectorOutput)
}

// ConnectorArrayInput is an input type that accepts ConnectorArray and ConnectorArrayOutput values.
// You can construct a concrete instance of `ConnectorArrayInput` via:
//
//	ConnectorArray{ ConnectorArgs{...} }
type ConnectorArrayInput interface {
	pulumi.Input

	ToConnectorArrayOutput() ConnectorArrayOutput
	ToConnectorArrayOutputWithContext(context.Context) ConnectorArrayOutput
}

type ConnectorArray []ConnectorInput

func (ConnectorArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Connector)(nil)).Elem()
}

func (i ConnectorArray) ToConnectorArrayOutput() ConnectorArrayOutput {
	return i.ToConnectorArrayOutputWithContext(context.Background())
}

func (i ConnectorArray) ToConnectorArrayOutputWithContext(ctx context.Context) ConnectorArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ConnectorArrayOutput)
}

// ConnectorMapInput is an input type that accepts ConnectorMap and ConnectorMapOutput values.
// You can construct a concrete instance of `ConnectorMapInput` via:
//
//	ConnectorMap{ "key": ConnectorArgs{...} }
type ConnectorMapInput interface {
	pulumi.Input

	ToConnectorMapOutput() ConnectorMapOutput
	ToConnectorMapOutputWithContext(context.Context) ConnectorMapOutput
}

type ConnectorMap map[string]ConnectorInput

func (ConnectorMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Connector)(nil)).Elem()
}

func (i ConnectorMap) ToConnectorMapOutput() ConnectorMapOutput {
	return i.ToConnectorMapOutputWithContext(context.Background())
}

func (i ConnectorMap) ToConnectorMapOutputWithContext(ctx context.Context) ConnectorMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ConnectorMapOutput)
}

type ConnectorOutput struct{ *pulumi.OutputState }

func (ConnectorOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Connector)(nil)).Elem()
}

func (o ConnectorOutput) ToConnectorOutput() ConnectorOutput {
	return o
}

func (o ConnectorOutput) ToConnectorOutputWithContext(ctx context.Context) ConnectorOutput {
	return o
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the comparment to create the connector in.
func (o ConnectorOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o ConnectorOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) The description of the resource. Avoid entering confidential information.
func (o ConnectorOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
func (o ConnectorOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o ConnectorOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
func (o ConnectorOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// *Please note this property is deprecated and will be removed on January 27, 2026. Use `lifecycleDetails` instead.* A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
func (o ConnectorOutput) LifecyleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringOutput { return v.LifecyleDetails }).(pulumi.StringOutput)
}

// (Updatable)
func (o ConnectorOutput) Source() ConnectorSourceOutput {
	return o.ApplyT(func(v *Connector) ConnectorSourceOutput { return v.Source }).(ConnectorSourceOutput)
}

// (Updatable) The target state for the service connector. Could be set to `ACTIVE` or `INACTIVE`.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ConnectorOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
func (o ConnectorOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// (Updatable)
func (o ConnectorOutput) Target() ConnectorTargetOutput {
	return o.ApplyT(func(v *Connector) ConnectorTargetOutput { return v.Target }).(ConnectorTargetOutput)
}

// (Updatable) The list of tasks.
func (o ConnectorOutput) Tasks() ConnectorTaskArrayOutput {
	return o.ApplyT(func(v *Connector) ConnectorTaskArrayOutput { return v.Tasks }).(ConnectorTaskArrayOutput)
}

// The date and time when the connector was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
func (o ConnectorOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time when the connector was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
func (o ConnectorOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type ConnectorArrayOutput struct{ *pulumi.OutputState }

func (ConnectorArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Connector)(nil)).Elem()
}

func (o ConnectorArrayOutput) ToConnectorArrayOutput() ConnectorArrayOutput {
	return o
}

func (o ConnectorArrayOutput) ToConnectorArrayOutputWithContext(ctx context.Context) ConnectorArrayOutput {
	return o
}

func (o ConnectorArrayOutput) Index(i pulumi.IntInput) ConnectorOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Connector {
		return vs[0].([]*Connector)[vs[1].(int)]
	}).(ConnectorOutput)
}

type ConnectorMapOutput struct{ *pulumi.OutputState }

func (ConnectorMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Connector)(nil)).Elem()
}

func (o ConnectorMapOutput) ToConnectorMapOutput() ConnectorMapOutput {
	return o
}

func (o ConnectorMapOutput) ToConnectorMapOutputWithContext(ctx context.Context) ConnectorMapOutput {
	return o
}

func (o ConnectorMapOutput) MapIndex(k pulumi.StringInput) ConnectorOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Connector {
		return vs[0].(map[string]*Connector)[vs[1].(string)]
	}).(ConnectorOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ConnectorInput)(nil)).Elem(), &Connector{})
	pulumi.RegisterInputType(reflect.TypeOf((*ConnectorArrayInput)(nil)).Elem(), ConnectorArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ConnectorMapInput)(nil)).Elem(), ConnectorMap{})
	pulumi.RegisterOutputType(ConnectorOutput{})
	pulumi.RegisterOutputType(ConnectorArrayOutput{})
	pulumi.RegisterOutputType(ConnectorMapOutput{})
}
