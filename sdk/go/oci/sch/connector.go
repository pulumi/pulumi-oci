// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package sch

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Service Connector resource in Oracle Cloud Infrastructure Service Connector Hub service.
//
// Creates a new service connector in the specified compartment.
// A service connector is a logically defined flow for moving data from
// a source service to a destination service in Oracle Cloud Infrastructure.
// For instructions, see
// [To create a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/managingconnectors.htm#create).
// For general information about service connectors, see
// [Service Connector Hub Overview](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm).
//
// For purposes of access control, you must provide the
// [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where
// you want the service connector to reside. Notice that the service connector
// doesn't have to be in the same compartment as the source or target services.
// For information about access control and compartments, see
// [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
//
// After you send your request, the new service connector's state is temporarily
// CREATING. When the state changes to ACTIVE, data begins transferring from the
// source service to the target service. For instructions on deactivating and
// activating service connectors, see
// [To activate or deactivate a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Sch"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Sch.NewConnector(ctx, "testServiceConnector", &Sch.ConnectorArgs{
//				CompartmentId: pulumi.Any(_var.Compartment_id),
//				DisplayName:   pulumi.Any(_var.Service_connector_display_name),
//				Source: &sch.ConnectorSourceArgs{
//					Kind: pulumi.Any(_var.Service_connector_source_kind),
//					Cursor: &sch.ConnectorSourceCursorArgs{
//						Kind: pulumi.Any(_var.Service_connector_source_cursor_kind),
//					},
//					LogSources: sch.ConnectorSourceLogSourceArray{
//						&sch.ConnectorSourceLogSourceArgs{
//							CompartmentId: pulumi.Any(_var.Compartment_id),
//							LogGroupId:    pulumi.Any(oci_logging_log_group.Test_log_group.Id),
//							LogId:         pulumi.Any(oci_logging_log.Test_log.Id),
//						},
//					},
//					MonitoringSources: sch.ConnectorSourceMonitoringSourceArray{
//						&sch.ConnectorSourceMonitoringSourceArgs{
//							CompartmentId: pulumi.Any(_var.Compartment_id),
//							NamespaceDetails: &sch.ConnectorSourceMonitoringSourceNamespaceDetailsArgs{
//								Kind: pulumi.Any(_var.Service_connector_source_monitoring_sources_namespace_details_kind),
//								Namespaces: sch.ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceArray{
//									&sch.ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceArgs{
//										Metrics: &sch.ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetricsArgs{
//											Kind: pulumi.Any(_var.Service_connector_source_monitoring_sources_namespace_details_namespaces_metrics_kind),
//										},
//										Namespace: pulumi.Any(_var.Service_connector_source_monitoring_sources_namespace_details_namespaces_namespace),
//									},
//								},
//							},
//						},
//					},
//					StreamId: pulumi.Any(oci_streaming_stream.Test_stream.Id),
//				},
//				Target: &sch.ConnectorTargetArgs{
//					Kind:                   pulumi.Any(_var.Service_connector_target_kind),
//					BatchRolloverSizeInMbs: pulumi.Any(_var.Service_connector_target_batch_rollover_size_in_mbs),
//					BatchRolloverTimeInMs:  pulumi.Any(_var.Service_connector_target_batch_rollover_time_in_ms),
//					Bucket:                 pulumi.Any(_var.Service_connector_target_bucket),
//					CompartmentId:          pulumi.Any(_var.Compartment_id),
//					Dimensions: sch.ConnectorTargetDimensionArray{
//						&sch.ConnectorTargetDimensionArgs{
//							DimensionValue: &sch.ConnectorTargetDimensionDimensionValueArgs{
//								Kind:  pulumi.Any(_var.Service_connector_target_dimensions_dimension_value_kind),
//								Path:  pulumi.Any(_var.Service_connector_target_dimensions_dimension_value_path),
//								Value: pulumi.Any(_var.Service_connector_target_dimensions_dimension_value_value),
//							},
//							Name: pulumi.Any(_var.Service_connector_target_dimensions_name),
//						},
//					},
//					EnableFormattedMessaging: pulumi.Any(_var.Service_connector_target_enable_formatted_messaging),
//					FunctionId:               pulumi.Any(oci_functions_function.Test_function.Id),
//					LogGroupId:               pulumi.Any(oci_logging_log_group.Test_log_group.Id),
//					LogSourceIdentifier:      pulumi.Any(_var.Service_connector_target_log_source_identifier),
//					Metric:                   pulumi.Any(_var.Service_connector_target_metric),
//					MetricNamespace:          pulumi.Any(_var.Service_connector_target_metric_namespace),
//					Namespace:                pulumi.Any(_var.Service_connector_target_namespace),
//					ObjectNamePrefix:         pulumi.Any(_var.Service_connector_target_object_name_prefix),
//					StreamId:                 pulumi.Any(oci_streaming_stream.Test_stream.Id),
//					TopicId:                  pulumi.Any(oci_ons_notification_topic.Test_notification_topic.Id),
//				},
//				DefinedTags: pulumi.AnyMap{
//					"foo-namespace.bar-key": pulumi.Any("value"),
//				},
//				Description: pulumi.Any(_var.Service_connector_description),
//				FreeformTags: pulumi.AnyMap{
//					"bar-key": pulumi.Any("value"),
//				},
//				Tasks: sch.ConnectorTaskArray{
//					&sch.ConnectorTaskArgs{
//						Kind:           pulumi.Any(_var.Service_connector_tasks_kind),
//						BatchSizeInKbs: pulumi.Any(_var.Service_connector_tasks_batch_size_in_kbs),
//						BatchTimeInSec: pulumi.Any(_var.Service_connector_tasks_batch_time_in_sec),
//						Condition:      pulumi.Any(_var.Service_connector_tasks_condition),
//						FunctionId:     pulumi.Any(oci_functions_function.Test_function.Id),
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
//
//	$ pulumi import oci:Sch/connector:Connector test_service_connector "id"
//
// ```
type Connector struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) The description of the resource. Avoid entering confidential information.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
	LifecyleDetails pulumi.StringOutput `pulumi:"lifecyleDetails"`
	// (Updatable) An object that represents the source of the flow defined by the service connector. An example source is the VCNFlow logs within the NetworkLogs group. For more information about flows defined by service connectors, see [Service Connector Hub Overview](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm). For configuration instructions, see [To create a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/managingconnectors.htm#create).
	Source ConnectorSourceOutput `pulumi:"source"`
	// (Updatable) The target state for the service connector. Could be set to `ACTIVE` or `INACTIVE`.
	State pulumi.StringOutput `pulumi:"state"`
	// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// (Updatable) An object that represents the target of the flow defined by the service connector. An example target is a stream (Streaming service). For more information about flows defined by service connectors, see [Service Connector Hub Overview](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm). For configuration instructions, see [To create a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/managingconnectors.htm#create).
	Target ConnectorTargetOutput `pulumi:"target"`
	// (Updatable) The list of tasks.
	Tasks ConnectorTaskArrayOutput `pulumi:"tasks"`
	// The date and time when the service connector was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time when the service connector was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
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
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description of the resource. Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
	LifecyleDetails *string `pulumi:"lifecyleDetails"`
	// (Updatable) An object that represents the source of the flow defined by the service connector. An example source is the VCNFlow logs within the NetworkLogs group. For more information about flows defined by service connectors, see [Service Connector Hub Overview](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm). For configuration instructions, see [To create a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/managingconnectors.htm#create).
	Source *ConnectorSource `pulumi:"source"`
	// (Updatable) The target state for the service connector. Could be set to `ACTIVE` or `INACTIVE`.
	State *string `pulumi:"state"`
	// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// (Updatable) An object that represents the target of the flow defined by the service connector. An example target is a stream (Streaming service). For more information about flows defined by service connectors, see [Service Connector Hub Overview](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm). For configuration instructions, see [To create a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/managingconnectors.htm#create).
	Target *ConnectorTarget `pulumi:"target"`
	// (Updatable) The list of tasks.
	Tasks []ConnectorTask `pulumi:"tasks"`
	// The date and time when the service connector was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time when the service connector was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type ConnectorState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description of the resource. Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
	LifecyleDetails pulumi.StringPtrInput
	// (Updatable) An object that represents the source of the flow defined by the service connector. An example source is the VCNFlow logs within the NetworkLogs group. For more information about flows defined by service connectors, see [Service Connector Hub Overview](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm). For configuration instructions, see [To create a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/managingconnectors.htm#create).
	Source ConnectorSourcePtrInput
	// (Updatable) The target state for the service connector. Could be set to `ACTIVE` or `INACTIVE`.
	State pulumi.StringPtrInput
	// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags pulumi.MapInput
	// (Updatable) An object that represents the target of the flow defined by the service connector. An example target is a stream (Streaming service). For more information about flows defined by service connectors, see [Service Connector Hub Overview](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm). For configuration instructions, see [To create a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/managingconnectors.htm#create).
	Target ConnectorTargetPtrInput
	// (Updatable) The list of tasks.
	Tasks ConnectorTaskArrayInput
	// The date and time when the service connector was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The date and time when the service connector was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
	TimeUpdated pulumi.StringPtrInput
}

func (ConnectorState) ElementType() reflect.Type {
	return reflect.TypeOf((*connectorState)(nil)).Elem()
}

type connectorArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description of the resource. Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) An object that represents the source of the flow defined by the service connector. An example source is the VCNFlow logs within the NetworkLogs group. For more information about flows defined by service connectors, see [Service Connector Hub Overview](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm). For configuration instructions, see [To create a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/managingconnectors.htm#create).
	Source ConnectorSource `pulumi:"source"`
	// (Updatable) The target state for the service connector. Could be set to `ACTIVE` or `INACTIVE`.
	State *string `pulumi:"state"`
	// (Updatable) An object that represents the target of the flow defined by the service connector. An example target is a stream (Streaming service). For more information about flows defined by service connectors, see [Service Connector Hub Overview](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm). For configuration instructions, see [To create a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/managingconnectors.htm#create).
	Target ConnectorTarget `pulumi:"target"`
	// (Updatable) The list of tasks.
	Tasks []ConnectorTask `pulumi:"tasks"`
}

// The set of arguments for constructing a Connector resource.
type ConnectorArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description of the resource. Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) An object that represents the source of the flow defined by the service connector. An example source is the VCNFlow logs within the NetworkLogs group. For more information about flows defined by service connectors, see [Service Connector Hub Overview](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm). For configuration instructions, see [To create a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/managingconnectors.htm#create).
	Source ConnectorSourceInput
	// (Updatable) The target state for the service connector. Could be set to `ACTIVE` or `INACTIVE`.
	State pulumi.StringPtrInput
	// (Updatable) An object that represents the target of the flow defined by the service connector. An example target is a stream (Streaming service). For more information about flows defined by service connectors, see [Service Connector Hub Overview](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm). For configuration instructions, see [To create a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/managingconnectors.htm#create).
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

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
func (o ConnectorOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o ConnectorOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Connector) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
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
func (o ConnectorOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Connector) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
func (o ConnectorOutput) LifecyleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringOutput { return v.LifecyleDetails }).(pulumi.StringOutput)
}

// (Updatable) An object that represents the source of the flow defined by the service connector. An example source is the VCNFlow logs within the NetworkLogs group. For more information about flows defined by service connectors, see [Service Connector Hub Overview](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm). For configuration instructions, see [To create a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/managingconnectors.htm#create).
func (o ConnectorOutput) Source() ConnectorSourceOutput {
	return o.ApplyT(func(v *Connector) ConnectorSourceOutput { return v.Source }).(ConnectorSourceOutput)
}

// (Updatable) The target state for the service connector. Could be set to `ACTIVE` or `INACTIVE`.
func (o ConnectorOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
func (o ConnectorOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Connector) pulumi.MapOutput { return v.SystemTags }).(pulumi.MapOutput)
}

// (Updatable) An object that represents the target of the flow defined by the service connector. An example target is a stream (Streaming service). For more information about flows defined by service connectors, see [Service Connector Hub Overview](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/overview.htm). For configuration instructions, see [To create a service connector](https://docs.cloud.oracle.com/iaas/Content/service-connector-hub/managingconnectors.htm#create).
func (o ConnectorOutput) Target() ConnectorTargetOutput {
	return o.ApplyT(func(v *Connector) ConnectorTargetOutput { return v.Target }).(ConnectorTargetOutput)
}

// (Updatable) The list of tasks.
func (o ConnectorOutput) Tasks() ConnectorTaskArrayOutput {
	return o.ApplyT(func(v *Connector) ConnectorTaskArrayOutput { return v.Tasks }).(ConnectorTaskArrayOutput)
}

// The date and time when the service connector was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
func (o ConnectorOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Connector) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time when the service connector was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
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