// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loganalytics

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Log Analytics Object Collection Rule resource in Oracle Cloud Infrastructure Log Analytics service.
//
// Create a configuration to collect logs from object storage bucket.
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
//			_, err := LogAnalytics.NewLogAnalyticsObjectCollectionRule(ctx, "testLogAnalyticsObjectCollectionRule", &LogAnalytics.LogAnalyticsObjectCollectionRuleArgs{
//				CompartmentId:  pulumi.Any(_var.Compartment_id),
//				LogGroupId:     pulumi.Any(oci_logging_log_group.Test_log_group.Id),
//				LogSourceName:  pulumi.Any(_var.Log_analytics_object_collection_rule_log_source_name),
//				Namespace:      pulumi.Any(_var.Log_analytics_object_collection_rule_namespace),
//				OsBucketName:   pulumi.Any(oci_objectstorage_bucket.Test_bucket.Name),
//				OsNamespace:    pulumi.Any(_var.Log_analytics_object_collection_rule_os_namespace),
//				CharEncoding:   pulumi.Any(_var.Log_analytics_object_collection_rule_char_encoding),
//				CollectionType: pulumi.Any(_var.Log_analytics_object_collection_rule_collection_type),
//				DefinedTags: pulumi.AnyMap{
//					"foo-namespace.bar-key": pulumi.Any("value"),
//				},
//				Description: pulumi.Any(_var.Log_analytics_object_collection_rule_description),
//				EntityId:    pulumi.Any(oci_log_analytics_entity.Test_entity.Id),
//				FreeformTags: pulumi.AnyMap{
//					"bar-key": pulumi.Any("value"),
//				},
//				ObjectNameFilters: pulumi.Any(_var.Log_analytics_object_collection_rule_object_name_filters),
//				Overrides:         pulumi.Any(_var.Log_analytics_object_collection_rule_overrides),
//				PollSince:         pulumi.Any(_var.Log_analytics_object_collection_rule_poll_since),
//				PollTill:          pulumi.Any(_var.Log_analytics_object_collection_rule_poll_till),
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
// LogAnalyticsObjectCollectionRules can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:LogAnalytics/logAnalyticsObjectCollectionRule:LogAnalyticsObjectCollectionRule test_log_analytics_object_collection_rule "namespaces/{namespaceName}/logAnalyticsObjectCollectionRules/{logAnalyticsObjectCollectionRuleId}"
//
// ```
type LogAnalyticsObjectCollectionRule struct {
	pulumi.CustomResourceState

	// (Updatable) An optional character encoding to aid in detecting the character encoding of the contents of the objects while processing. It is recommended to set this value as ISO_8589_1 when configuring content of the objects having more numeric characters, and very few alphabets. For e.g. this applies when configuring VCN Flow Logs.
	CharEncoding pulumi.StringOutput `pulumi:"charEncoding"`
	// The type of collection. Supported collection types: LIVE, HISTORIC, HISTORIC_LIVE
	CollectionType pulumi.StringOutput `pulumi:"collectionType"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A string that describes the details of the rule. It does not have to be unique, and can be changed. Avoid entering confidential information.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Logging Analytics entity OCID. Associates the processed logs with the given entity (optional).
	EntityId pulumi.StringOutput `pulumi:"entityId"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// A detailed status of the life cycle state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// (Updatable) Logging Analytics Log group OCID to associate the processed logs with.
	LogGroupId pulumi.StringOutput `pulumi:"logGroupId"`
	// (Updatable) Name of the Logging Analytics Source to use for the processing.
	LogSourceName pulumi.StringOutput `pulumi:"logSourceName"`
	// A unique name given to the rule. The name must be unique within the tenancy, and cannot be modified.
	Name pulumi.StringOutput `pulumi:"name"`
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringOutput `pulumi:"namespace"`
	// (Updatable) When the filters are provided, only the objects matching the filters are picked up for processing. The matchType supported is exact match and accommodates wildcard "*". For more information on filters, see [Event Filters](https://docs.oracle.com/en-us/iaas/Content/Events/Concepts/filterevents.htm).
	ObjectNameFilters pulumi.StringArrayOutput `pulumi:"objectNameFilters"`
	// Name of the Object Storage bucket.
	OsBucketName pulumi.StringOutput `pulumi:"osBucketName"`
	// Object Storage namespace.
	OsNamespace pulumi.StringOutput `pulumi:"osNamespace"`
	// (Updatable) The override is used to modify some important configuration properties for objects matching a specific pattern inside the bucket. Supported propeties for override are - logSourceName, charEncoding. Supported matchType for override are "contains".
	Overrides LogAnalyticsObjectCollectionRuleOverrideArrayOutput `pulumi:"overrides"`
	// The oldest time of the file in the bucket to consider for collection. Accepted values are: BEGINNING or CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollSince value other than CURRENT_TIME will result in error.
	PollSince pulumi.StringOutput `pulumi:"pollSince"`
	// The oldest time of the file in the bucket to consider for collection. Accepted values are: CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollTill will result in error.
	PollTill pulumi.StringOutput `pulumi:"pollTill"`
	// The current state of the rule.
	State pulumi.StringOutput `pulumi:"state"`
	// The time when this rule was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time when this rule was last updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewLogAnalyticsObjectCollectionRule registers a new resource with the given unique name, arguments, and options.
func NewLogAnalyticsObjectCollectionRule(ctx *pulumi.Context,
	name string, args *LogAnalyticsObjectCollectionRuleArgs, opts ...pulumi.ResourceOption) (*LogAnalyticsObjectCollectionRule, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.LogGroupId == nil {
		return nil, errors.New("invalid value for required argument 'LogGroupId'")
	}
	if args.LogSourceName == nil {
		return nil, errors.New("invalid value for required argument 'LogSourceName'")
	}
	if args.Namespace == nil {
		return nil, errors.New("invalid value for required argument 'Namespace'")
	}
	if args.OsBucketName == nil {
		return nil, errors.New("invalid value for required argument 'OsBucketName'")
	}
	if args.OsNamespace == nil {
		return nil, errors.New("invalid value for required argument 'OsNamespace'")
	}
	var resource LogAnalyticsObjectCollectionRule
	err := ctx.RegisterResource("oci:LogAnalytics/logAnalyticsObjectCollectionRule:LogAnalyticsObjectCollectionRule", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLogAnalyticsObjectCollectionRule gets an existing LogAnalyticsObjectCollectionRule resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLogAnalyticsObjectCollectionRule(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LogAnalyticsObjectCollectionRuleState, opts ...pulumi.ResourceOption) (*LogAnalyticsObjectCollectionRule, error) {
	var resource LogAnalyticsObjectCollectionRule
	err := ctx.ReadResource("oci:LogAnalytics/logAnalyticsObjectCollectionRule:LogAnalyticsObjectCollectionRule", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LogAnalyticsObjectCollectionRule resources.
type logAnalyticsObjectCollectionRuleState struct {
	// (Updatable) An optional character encoding to aid in detecting the character encoding of the contents of the objects while processing. It is recommended to set this value as ISO_8589_1 when configuring content of the objects having more numeric characters, and very few alphabets. For e.g. this applies when configuring VCN Flow Logs.
	CharEncoding *string `pulumi:"charEncoding"`
	// The type of collection. Supported collection types: LIVE, HISTORIC, HISTORIC_LIVE
	CollectionType *string `pulumi:"collectionType"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A string that describes the details of the rule. It does not have to be unique, and can be changed. Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// (Updatable) Logging Analytics entity OCID. Associates the processed logs with the given entity (optional).
	EntityId *string `pulumi:"entityId"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A detailed status of the life cycle state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// (Updatable) Logging Analytics Log group OCID to associate the processed logs with.
	LogGroupId *string `pulumi:"logGroupId"`
	// (Updatable) Name of the Logging Analytics Source to use for the processing.
	LogSourceName *string `pulumi:"logSourceName"`
	// A unique name given to the rule. The name must be unique within the tenancy, and cannot be modified.
	Name *string `pulumi:"name"`
	// The Logging Analytics namespace used for the request.
	Namespace *string `pulumi:"namespace"`
	// (Updatable) When the filters are provided, only the objects matching the filters are picked up for processing. The matchType supported is exact match and accommodates wildcard "*". For more information on filters, see [Event Filters](https://docs.oracle.com/en-us/iaas/Content/Events/Concepts/filterevents.htm).
	ObjectNameFilters []string `pulumi:"objectNameFilters"`
	// Name of the Object Storage bucket.
	OsBucketName *string `pulumi:"osBucketName"`
	// Object Storage namespace.
	OsNamespace *string `pulumi:"osNamespace"`
	// (Updatable) The override is used to modify some important configuration properties for objects matching a specific pattern inside the bucket. Supported propeties for override are - logSourceName, charEncoding. Supported matchType for override are "contains".
	Overrides []LogAnalyticsObjectCollectionRuleOverride `pulumi:"overrides"`
	// The oldest time of the file in the bucket to consider for collection. Accepted values are: BEGINNING or CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollSince value other than CURRENT_TIME will result in error.
	PollSince *string `pulumi:"pollSince"`
	// The oldest time of the file in the bucket to consider for collection. Accepted values are: CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollTill will result in error.
	PollTill *string `pulumi:"pollTill"`
	// The current state of the rule.
	State *string `pulumi:"state"`
	// The time when this rule was created. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time when this rule was last updated. An RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type LogAnalyticsObjectCollectionRuleState struct {
	// (Updatable) An optional character encoding to aid in detecting the character encoding of the contents of the objects while processing. It is recommended to set this value as ISO_8589_1 when configuring content of the objects having more numeric characters, and very few alphabets. For e.g. this applies when configuring VCN Flow Logs.
	CharEncoding pulumi.StringPtrInput
	// The type of collection. Supported collection types: LIVE, HISTORIC, HISTORIC_LIVE
	CollectionType pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A string that describes the details of the rule. It does not have to be unique, and can be changed. Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// (Updatable) Logging Analytics entity OCID. Associates the processed logs with the given entity (optional).
	EntityId pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// A detailed status of the life cycle state.
	LifecycleDetails pulumi.StringPtrInput
	// (Updatable) Logging Analytics Log group OCID to associate the processed logs with.
	LogGroupId pulumi.StringPtrInput
	// (Updatable) Name of the Logging Analytics Source to use for the processing.
	LogSourceName pulumi.StringPtrInput
	// A unique name given to the rule. The name must be unique within the tenancy, and cannot be modified.
	Name pulumi.StringPtrInput
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringPtrInput
	// (Updatable) When the filters are provided, only the objects matching the filters are picked up for processing. The matchType supported is exact match and accommodates wildcard "*". For more information on filters, see [Event Filters](https://docs.oracle.com/en-us/iaas/Content/Events/Concepts/filterevents.htm).
	ObjectNameFilters pulumi.StringArrayInput
	// Name of the Object Storage bucket.
	OsBucketName pulumi.StringPtrInput
	// Object Storage namespace.
	OsNamespace pulumi.StringPtrInput
	// (Updatable) The override is used to modify some important configuration properties for objects matching a specific pattern inside the bucket. Supported propeties for override are - logSourceName, charEncoding. Supported matchType for override are "contains".
	Overrides LogAnalyticsObjectCollectionRuleOverrideArrayInput
	// The oldest time of the file in the bucket to consider for collection. Accepted values are: BEGINNING or CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollSince value other than CURRENT_TIME will result in error.
	PollSince pulumi.StringPtrInput
	// The oldest time of the file in the bucket to consider for collection. Accepted values are: CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollTill will result in error.
	PollTill pulumi.StringPtrInput
	// The current state of the rule.
	State pulumi.StringPtrInput
	// The time when this rule was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time when this rule was last updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (LogAnalyticsObjectCollectionRuleState) ElementType() reflect.Type {
	return reflect.TypeOf((*logAnalyticsObjectCollectionRuleState)(nil)).Elem()
}

type logAnalyticsObjectCollectionRuleArgs struct {
	// (Updatable) An optional character encoding to aid in detecting the character encoding of the contents of the objects while processing. It is recommended to set this value as ISO_8589_1 when configuring content of the objects having more numeric characters, and very few alphabets. For e.g. this applies when configuring VCN Flow Logs.
	CharEncoding *string `pulumi:"charEncoding"`
	// The type of collection. Supported collection types: LIVE, HISTORIC, HISTORIC_LIVE
	CollectionType *string `pulumi:"collectionType"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A string that describes the details of the rule. It does not have to be unique, and can be changed. Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// (Updatable) Logging Analytics entity OCID. Associates the processed logs with the given entity (optional).
	EntityId *string `pulumi:"entityId"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Logging Analytics Log group OCID to associate the processed logs with.
	LogGroupId string `pulumi:"logGroupId"`
	// (Updatable) Name of the Logging Analytics Source to use for the processing.
	LogSourceName string `pulumi:"logSourceName"`
	// A unique name given to the rule. The name must be unique within the tenancy, and cannot be modified.
	Name *string `pulumi:"name"`
	// The Logging Analytics namespace used for the request.
	Namespace string `pulumi:"namespace"`
	// (Updatable) When the filters are provided, only the objects matching the filters are picked up for processing. The matchType supported is exact match and accommodates wildcard "*". For more information on filters, see [Event Filters](https://docs.oracle.com/en-us/iaas/Content/Events/Concepts/filterevents.htm).
	ObjectNameFilters []string `pulumi:"objectNameFilters"`
	// Name of the Object Storage bucket.
	OsBucketName string `pulumi:"osBucketName"`
	// Object Storage namespace.
	OsNamespace string `pulumi:"osNamespace"`
	// (Updatable) The override is used to modify some important configuration properties for objects matching a specific pattern inside the bucket. Supported propeties for override are - logSourceName, charEncoding. Supported matchType for override are "contains".
	Overrides []LogAnalyticsObjectCollectionRuleOverride `pulumi:"overrides"`
	// The oldest time of the file in the bucket to consider for collection. Accepted values are: BEGINNING or CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollSince value other than CURRENT_TIME will result in error.
	PollSince *string `pulumi:"pollSince"`
	// The oldest time of the file in the bucket to consider for collection. Accepted values are: CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollTill will result in error.
	PollTill *string `pulumi:"pollTill"`
}

// The set of arguments for constructing a LogAnalyticsObjectCollectionRule resource.
type LogAnalyticsObjectCollectionRuleArgs struct {
	// (Updatable) An optional character encoding to aid in detecting the character encoding of the contents of the objects while processing. It is recommended to set this value as ISO_8589_1 when configuring content of the objects having more numeric characters, and very few alphabets. For e.g. this applies when configuring VCN Flow Logs.
	CharEncoding pulumi.StringPtrInput
	// The type of collection. Supported collection types: LIVE, HISTORIC, HISTORIC_LIVE
	CollectionType pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A string that describes the details of the rule. It does not have to be unique, and can be changed. Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// (Updatable) Logging Analytics entity OCID. Associates the processed logs with the given entity (optional).
	EntityId pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Logging Analytics Log group OCID to associate the processed logs with.
	LogGroupId pulumi.StringInput
	// (Updatable) Name of the Logging Analytics Source to use for the processing.
	LogSourceName pulumi.StringInput
	// A unique name given to the rule. The name must be unique within the tenancy, and cannot be modified.
	Name pulumi.StringPtrInput
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringInput
	// (Updatable) When the filters are provided, only the objects matching the filters are picked up for processing. The matchType supported is exact match and accommodates wildcard "*". For more information on filters, see [Event Filters](https://docs.oracle.com/en-us/iaas/Content/Events/Concepts/filterevents.htm).
	ObjectNameFilters pulumi.StringArrayInput
	// Name of the Object Storage bucket.
	OsBucketName pulumi.StringInput
	// Object Storage namespace.
	OsNamespace pulumi.StringInput
	// (Updatable) The override is used to modify some important configuration properties for objects matching a specific pattern inside the bucket. Supported propeties for override are - logSourceName, charEncoding. Supported matchType for override are "contains".
	Overrides LogAnalyticsObjectCollectionRuleOverrideArrayInput
	// The oldest time of the file in the bucket to consider for collection. Accepted values are: BEGINNING or CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollSince value other than CURRENT_TIME will result in error.
	PollSince pulumi.StringPtrInput
	// The oldest time of the file in the bucket to consider for collection. Accepted values are: CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollTill will result in error.
	PollTill pulumi.StringPtrInput
}

func (LogAnalyticsObjectCollectionRuleArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*logAnalyticsObjectCollectionRuleArgs)(nil)).Elem()
}

type LogAnalyticsObjectCollectionRuleInput interface {
	pulumi.Input

	ToLogAnalyticsObjectCollectionRuleOutput() LogAnalyticsObjectCollectionRuleOutput
	ToLogAnalyticsObjectCollectionRuleOutputWithContext(ctx context.Context) LogAnalyticsObjectCollectionRuleOutput
}

func (*LogAnalyticsObjectCollectionRule) ElementType() reflect.Type {
	return reflect.TypeOf((**LogAnalyticsObjectCollectionRule)(nil)).Elem()
}

func (i *LogAnalyticsObjectCollectionRule) ToLogAnalyticsObjectCollectionRuleOutput() LogAnalyticsObjectCollectionRuleOutput {
	return i.ToLogAnalyticsObjectCollectionRuleOutputWithContext(context.Background())
}

func (i *LogAnalyticsObjectCollectionRule) ToLogAnalyticsObjectCollectionRuleOutputWithContext(ctx context.Context) LogAnalyticsObjectCollectionRuleOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsObjectCollectionRuleOutput)
}

// LogAnalyticsObjectCollectionRuleArrayInput is an input type that accepts LogAnalyticsObjectCollectionRuleArray and LogAnalyticsObjectCollectionRuleArrayOutput values.
// You can construct a concrete instance of `LogAnalyticsObjectCollectionRuleArrayInput` via:
//
//	LogAnalyticsObjectCollectionRuleArray{ LogAnalyticsObjectCollectionRuleArgs{...} }
type LogAnalyticsObjectCollectionRuleArrayInput interface {
	pulumi.Input

	ToLogAnalyticsObjectCollectionRuleArrayOutput() LogAnalyticsObjectCollectionRuleArrayOutput
	ToLogAnalyticsObjectCollectionRuleArrayOutputWithContext(context.Context) LogAnalyticsObjectCollectionRuleArrayOutput
}

type LogAnalyticsObjectCollectionRuleArray []LogAnalyticsObjectCollectionRuleInput

func (LogAnalyticsObjectCollectionRuleArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LogAnalyticsObjectCollectionRule)(nil)).Elem()
}

func (i LogAnalyticsObjectCollectionRuleArray) ToLogAnalyticsObjectCollectionRuleArrayOutput() LogAnalyticsObjectCollectionRuleArrayOutput {
	return i.ToLogAnalyticsObjectCollectionRuleArrayOutputWithContext(context.Background())
}

func (i LogAnalyticsObjectCollectionRuleArray) ToLogAnalyticsObjectCollectionRuleArrayOutputWithContext(ctx context.Context) LogAnalyticsObjectCollectionRuleArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsObjectCollectionRuleArrayOutput)
}

// LogAnalyticsObjectCollectionRuleMapInput is an input type that accepts LogAnalyticsObjectCollectionRuleMap and LogAnalyticsObjectCollectionRuleMapOutput values.
// You can construct a concrete instance of `LogAnalyticsObjectCollectionRuleMapInput` via:
//
//	LogAnalyticsObjectCollectionRuleMap{ "key": LogAnalyticsObjectCollectionRuleArgs{...} }
type LogAnalyticsObjectCollectionRuleMapInput interface {
	pulumi.Input

	ToLogAnalyticsObjectCollectionRuleMapOutput() LogAnalyticsObjectCollectionRuleMapOutput
	ToLogAnalyticsObjectCollectionRuleMapOutputWithContext(context.Context) LogAnalyticsObjectCollectionRuleMapOutput
}

type LogAnalyticsObjectCollectionRuleMap map[string]LogAnalyticsObjectCollectionRuleInput

func (LogAnalyticsObjectCollectionRuleMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LogAnalyticsObjectCollectionRule)(nil)).Elem()
}

func (i LogAnalyticsObjectCollectionRuleMap) ToLogAnalyticsObjectCollectionRuleMapOutput() LogAnalyticsObjectCollectionRuleMapOutput {
	return i.ToLogAnalyticsObjectCollectionRuleMapOutputWithContext(context.Background())
}

func (i LogAnalyticsObjectCollectionRuleMap) ToLogAnalyticsObjectCollectionRuleMapOutputWithContext(ctx context.Context) LogAnalyticsObjectCollectionRuleMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsObjectCollectionRuleMapOutput)
}

type LogAnalyticsObjectCollectionRuleOutput struct{ *pulumi.OutputState }

func (LogAnalyticsObjectCollectionRuleOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**LogAnalyticsObjectCollectionRule)(nil)).Elem()
}

func (o LogAnalyticsObjectCollectionRuleOutput) ToLogAnalyticsObjectCollectionRuleOutput() LogAnalyticsObjectCollectionRuleOutput {
	return o
}

func (o LogAnalyticsObjectCollectionRuleOutput) ToLogAnalyticsObjectCollectionRuleOutputWithContext(ctx context.Context) LogAnalyticsObjectCollectionRuleOutput {
	return o
}

// (Updatable) An optional character encoding to aid in detecting the character encoding of the contents of the objects while processing. It is recommended to set this value as ISO_8589_1 when configuring content of the objects having more numeric characters, and very few alphabets. For e.g. this applies when configuring VCN Flow Logs.
func (o LogAnalyticsObjectCollectionRuleOutput) CharEncoding() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.CharEncoding }).(pulumi.StringOutput)
}

// The type of collection. Supported collection types: LIVE, HISTORIC, HISTORIC_LIVE
func (o LogAnalyticsObjectCollectionRuleOutput) CollectionType() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.CollectionType }).(pulumi.StringOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
func (o LogAnalyticsObjectCollectionRuleOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LogAnalyticsObjectCollectionRuleOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) A string that describes the details of the rule. It does not have to be unique, and can be changed. Avoid entering confidential information.
func (o LogAnalyticsObjectCollectionRuleOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) Logging Analytics entity OCID. Associates the processed logs with the given entity (optional).
func (o LogAnalyticsObjectCollectionRuleOutput) EntityId() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.EntityId }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LogAnalyticsObjectCollectionRuleOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// A detailed status of the life cycle state.
func (o LogAnalyticsObjectCollectionRuleOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// (Updatable) Logging Analytics Log group OCID to associate the processed logs with.
func (o LogAnalyticsObjectCollectionRuleOutput) LogGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.LogGroupId }).(pulumi.StringOutput)
}

// (Updatable) Name of the Logging Analytics Source to use for the processing.
func (o LogAnalyticsObjectCollectionRuleOutput) LogSourceName() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.LogSourceName }).(pulumi.StringOutput)
}

// A unique name given to the rule. The name must be unique within the tenancy, and cannot be modified.
func (o LogAnalyticsObjectCollectionRuleOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// The Logging Analytics namespace used for the request.
func (o LogAnalyticsObjectCollectionRuleOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.Namespace }).(pulumi.StringOutput)
}

// (Updatable) When the filters are provided, only the objects matching the filters are picked up for processing. The matchType supported is exact match and accommodates wildcard "*". For more information on filters, see [Event Filters](https://docs.oracle.com/en-us/iaas/Content/Events/Concepts/filterevents.htm).
func (o LogAnalyticsObjectCollectionRuleOutput) ObjectNameFilters() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringArrayOutput { return v.ObjectNameFilters }).(pulumi.StringArrayOutput)
}

// Name of the Object Storage bucket.
func (o LogAnalyticsObjectCollectionRuleOutput) OsBucketName() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.OsBucketName }).(pulumi.StringOutput)
}

// Object Storage namespace.
func (o LogAnalyticsObjectCollectionRuleOutput) OsNamespace() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.OsNamespace }).(pulumi.StringOutput)
}

// (Updatable) The override is used to modify some important configuration properties for objects matching a specific pattern inside the bucket. Supported propeties for override are - logSourceName, charEncoding. Supported matchType for override are "contains".
func (o LogAnalyticsObjectCollectionRuleOutput) Overrides() LogAnalyticsObjectCollectionRuleOverrideArrayOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) LogAnalyticsObjectCollectionRuleOverrideArrayOutput {
		return v.Overrides
	}).(LogAnalyticsObjectCollectionRuleOverrideArrayOutput)
}

// The oldest time of the file in the bucket to consider for collection. Accepted values are: BEGINNING or CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollSince value other than CURRENT_TIME will result in error.
func (o LogAnalyticsObjectCollectionRuleOutput) PollSince() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.PollSince }).(pulumi.StringOutput)
}

// The oldest time of the file in the bucket to consider for collection. Accepted values are: CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollTill will result in error.
func (o LogAnalyticsObjectCollectionRuleOutput) PollTill() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.PollTill }).(pulumi.StringOutput)
}

// The current state of the rule.
func (o LogAnalyticsObjectCollectionRuleOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The time when this rule was created. An RFC3339 formatted datetime string.
func (o LogAnalyticsObjectCollectionRuleOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when this rule was last updated. An RFC3339 formatted datetime string.
func (o LogAnalyticsObjectCollectionRuleOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *LogAnalyticsObjectCollectionRule) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type LogAnalyticsObjectCollectionRuleArrayOutput struct{ *pulumi.OutputState }

func (LogAnalyticsObjectCollectionRuleArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LogAnalyticsObjectCollectionRule)(nil)).Elem()
}

func (o LogAnalyticsObjectCollectionRuleArrayOutput) ToLogAnalyticsObjectCollectionRuleArrayOutput() LogAnalyticsObjectCollectionRuleArrayOutput {
	return o
}

func (o LogAnalyticsObjectCollectionRuleArrayOutput) ToLogAnalyticsObjectCollectionRuleArrayOutputWithContext(ctx context.Context) LogAnalyticsObjectCollectionRuleArrayOutput {
	return o
}

func (o LogAnalyticsObjectCollectionRuleArrayOutput) Index(i pulumi.IntInput) LogAnalyticsObjectCollectionRuleOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *LogAnalyticsObjectCollectionRule {
		return vs[0].([]*LogAnalyticsObjectCollectionRule)[vs[1].(int)]
	}).(LogAnalyticsObjectCollectionRuleOutput)
}

type LogAnalyticsObjectCollectionRuleMapOutput struct{ *pulumi.OutputState }

func (LogAnalyticsObjectCollectionRuleMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LogAnalyticsObjectCollectionRule)(nil)).Elem()
}

func (o LogAnalyticsObjectCollectionRuleMapOutput) ToLogAnalyticsObjectCollectionRuleMapOutput() LogAnalyticsObjectCollectionRuleMapOutput {
	return o
}

func (o LogAnalyticsObjectCollectionRuleMapOutput) ToLogAnalyticsObjectCollectionRuleMapOutputWithContext(ctx context.Context) LogAnalyticsObjectCollectionRuleMapOutput {
	return o
}

func (o LogAnalyticsObjectCollectionRuleMapOutput) MapIndex(k pulumi.StringInput) LogAnalyticsObjectCollectionRuleOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *LogAnalyticsObjectCollectionRule {
		return vs[0].(map[string]*LogAnalyticsObjectCollectionRule)[vs[1].(string)]
	}).(LogAnalyticsObjectCollectionRuleOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*LogAnalyticsObjectCollectionRuleInput)(nil)).Elem(), &LogAnalyticsObjectCollectionRule{})
	pulumi.RegisterInputType(reflect.TypeOf((*LogAnalyticsObjectCollectionRuleArrayInput)(nil)).Elem(), LogAnalyticsObjectCollectionRuleArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*LogAnalyticsObjectCollectionRuleMapInput)(nil)).Elem(), LogAnalyticsObjectCollectionRuleMap{})
	pulumi.RegisterOutputType(LogAnalyticsObjectCollectionRuleOutput{})
	pulumi.RegisterOutputType(LogAnalyticsObjectCollectionRuleArrayOutput{})
	pulumi.RegisterOutputType(LogAnalyticsObjectCollectionRuleMapOutput{})
}