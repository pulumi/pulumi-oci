// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loganalytics

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Log Analytics Entities in Oracle Cloud Infrastructure Log Analytics service.
//
// Return a list of log analytics entities.
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
//			_, err := loganalytics.GetLogAnalyticsEntities(ctx, &loganalytics.GetLogAnalyticsEntitiesArgs{
//				CompartmentId:                compartmentId,
//				Namespace:                    logAnalyticsEntityNamespace,
//				CloudResourceId:              pulumi.StringRef(logAnalyticsEntityCloudResourceId),
//				DefinedTagEquals:             logAnalyticsEntityDefinedTagEquals,
//				DefinedTagExists:             logAnalyticsEntityDefinedTagExists,
//				EntityTypeNames:              logAnalyticsEntityEntityTypeName,
//				FreeformTagEquals:            logAnalyticsEntityFreeformTagEquals,
//				FreeformTagExists:            logAnalyticsEntityFreeformTagExists,
//				Hostname:                     pulumi.StringRef(logAnalyticsEntityHostname),
//				HostnameContains:             pulumi.StringRef(logAnalyticsEntityHostnameContains),
//				IsManagementAgentIdNull:      pulumi.StringRef(logAnalyticsEntityIsManagementAgentIdNull),
//				IsShowAssociatedSourcesCount: pulumi.BoolRef(logAnalyticsEntityIsShowAssociatedSourcesCount),
//				LifecycleDetailsContains:     pulumi.StringRef(logAnalyticsEntityLifecycleDetailsContains),
//				MetadataEquals:               logAnalyticsEntityMetadataEquals,
//				Name:                         pulumi.StringRef(logAnalyticsEntityName),
//				NameContains:                 pulumi.StringRef(logAnalyticsEntityNameContains),
//				SourceId:                     pulumi.StringRef(testSource.Id),
//				State:                        pulumi.StringRef(logAnalyticsEntityState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetLogAnalyticsEntities(ctx *pulumi.Context, args *GetLogAnalyticsEntitiesArgs, opts ...pulumi.InvokeOption) (*GetLogAnalyticsEntitiesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetLogAnalyticsEntitiesResult
	err := ctx.Invoke("oci:LogAnalytics/getLogAnalyticsEntities:getLogAnalyticsEntities", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getLogAnalyticsEntities.
type GetLogAnalyticsEntitiesArgs struct {
	// A filter to return only log analytics entities whose cloudResourceId matches the cloudResourceId given.
	CloudResourceId *string `pulumi:"cloudResourceId"`
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A list of tag filters to apply.  Only entities with a defined tag matching the value will be returned. Each item in the list has the format "{namespace}.{tagName}.{value}".  All inputs are case-insensitive. Multiple values for the same key (i.e. same namespace and tag name) are interpreted as "OR". Values for different keys (i.e. different namespaces, different tag names, or both) are interpreted as "AND".
	DefinedTagEquals []string `pulumi:"definedTagEquals"`
	// A list of tag existence filters to apply.  Only entities for which the specified defined tags exist will be returned. Each item in the list has the format "{namespace}.{tagName}.true" (for checking existence of a defined tag) or "{namespace}.true".  All inputs are case-insensitive. Currently, only existence ("true" at the end) is supported. Absence ("false" at the end) is not supported. Multiple values for the same key (i.e. same namespace and tag name) are interpreted as "OR". Values for different keys (i.e. different namespaces, different tag names, or both) are interpreted as "AND".
	DefinedTagExists []string `pulumi:"definedTagExists"`
	// A filter to return only log analytics entities whose entityTypeName matches the entire log analytics entity type name of one of the entityTypeNames given in the list. The match is case-insensitive.
	EntityTypeNames []string                        `pulumi:"entityTypeNames"`
	Filters         []GetLogAnalyticsEntitiesFilter `pulumi:"filters"`
	// A list of tag filters to apply.  Only entities with a freeform tag matching the value will be returned. The key for each tag is "{tagName}.{value}".  All inputs are case-insensitive. Multiple values for the same tag name are interpreted as "OR".  Values for different tag names are interpreted as "AND".
	FreeformTagEquals []string `pulumi:"freeformTagEquals"`
	// A list of tag existence filters to apply.  Only entities for which the specified freeform tags exist the value will be returned. The key for each tag is "{tagName}.true".  All inputs are case-insensitive. Currently, only existence ("true" at the end) is supported. Absence ("false" at the end) is not supported. Multiple values for different tag names are interpreted as "AND".
	FreeformTagExists []string `pulumi:"freeformTagExists"`
	// A filter to return only log analytics entities whose hostname matches the entire hostname given.
	Hostname *string `pulumi:"hostname"`
	// A filter to return only log analytics entities whose hostname contains the substring given. The match is case-insensitive.
	HostnameContains *string `pulumi:"hostnameContains"`
	// A filter to return only those log analytics entities whose managementAgentId is null or is not null.
	IsManagementAgentIdNull *string `pulumi:"isManagementAgentIdNull"`
	// Option to return count of associated log sources for log analytics entity(s).
	IsShowAssociatedSourcesCount *bool `pulumi:"isShowAssociatedSourcesCount"`
	// A filter to return only log analytics entities whose lifecycleDetails contains the specified string.
	LifecycleDetailsContains *string `pulumi:"lifecycleDetailsContains"`
	// A filter to return only log analytics entities whose metadata name, value and type matches the specified string. Each item in the array has the format "{name}:{value}:{type}".  All inputs are case-insensitive.
	MetadataEquals []string `pulumi:"metadataEquals"`
	// A filter to return only log analytics entities whose name matches the entire name given. The match is case-insensitive.
	Name *string `pulumi:"name"`
	// A filter to return only log analytics entities whose name contains the name given. The match is case-insensitive.
	NameContains *string `pulumi:"nameContains"`
	// The Logging Analytics namespace used for the request.
	Namespace string `pulumi:"namespace"`
	// A filter to return only log analytics entities whose sourceId matches the sourceId given.
	SourceId *string `pulumi:"sourceId"`
	// A filter to return only those log analytics entities with the specified lifecycle state. The state value is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getLogAnalyticsEntities.
type GetLogAnalyticsEntitiesResult struct {
	// The OCID of the Cloud resource which this entity is a representation of. This may be blank when the entity represents a non-cloud resource that the customer may have on their premises.
	CloudResourceId *string `pulumi:"cloudResourceId"`
	// Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId    string   `pulumi:"compartmentId"`
	DefinedTagEquals []string `pulumi:"definedTagEquals"`
	DefinedTagExists []string `pulumi:"definedTagExists"`
	// Log analytics entity type name.
	EntityTypeNames   []string                        `pulumi:"entityTypeNames"`
	Filters           []GetLogAnalyticsEntitiesFilter `pulumi:"filters"`
	FreeformTagEquals []string                        `pulumi:"freeformTagEquals"`
	FreeformTagExists []string                        `pulumi:"freeformTagExists"`
	// The hostname where the entity represented here is actually present. This would be the output one would get if they run `echo $HOSTNAME` on Linux or an equivalent OS command. This may be different from management agents host since logs may be collected remotely.
	Hostname         *string `pulumi:"hostname"`
	HostnameContains *string `pulumi:"hostnameContains"`
	// The provider-assigned unique ID for this managed resource.
	Id                           string  `pulumi:"id"`
	IsManagementAgentIdNull      *string `pulumi:"isManagementAgentIdNull"`
	IsShowAssociatedSourcesCount *bool   `pulumi:"isShowAssociatedSourcesCount"`
	LifecycleDetailsContains     *string `pulumi:"lifecycleDetailsContains"`
	// The list of log_analytics_entity_collection.
	LogAnalyticsEntityCollections []GetLogAnalyticsEntitiesLogAnalyticsEntityCollection `pulumi:"logAnalyticsEntityCollections"`
	MetadataEquals                []string                                              `pulumi:"metadataEquals"`
	// Log analytics entity name.
	Name         *string `pulumi:"name"`
	NameContains *string `pulumi:"nameContains"`
	Namespace    string  `pulumi:"namespace"`
	// This indicates the type of source. It is primarily for Enterprise Manager Repository ID.
	SourceId *string `pulumi:"sourceId"`
	// The current state of the log analytics entity.
	State *string `pulumi:"state"`
}

func GetLogAnalyticsEntitiesOutput(ctx *pulumi.Context, args GetLogAnalyticsEntitiesOutputArgs, opts ...pulumi.InvokeOption) GetLogAnalyticsEntitiesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetLogAnalyticsEntitiesResultOutput, error) {
			args := v.(GetLogAnalyticsEntitiesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:LogAnalytics/getLogAnalyticsEntities:getLogAnalyticsEntities", args, GetLogAnalyticsEntitiesResultOutput{}, options).(GetLogAnalyticsEntitiesResultOutput), nil
		}).(GetLogAnalyticsEntitiesResultOutput)
}

// A collection of arguments for invoking getLogAnalyticsEntities.
type GetLogAnalyticsEntitiesOutputArgs struct {
	// A filter to return only log analytics entities whose cloudResourceId matches the cloudResourceId given.
	CloudResourceId pulumi.StringPtrInput `pulumi:"cloudResourceId"`
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A list of tag filters to apply.  Only entities with a defined tag matching the value will be returned. Each item in the list has the format "{namespace}.{tagName}.{value}".  All inputs are case-insensitive. Multiple values for the same key (i.e. same namespace and tag name) are interpreted as "OR". Values for different keys (i.e. different namespaces, different tag names, or both) are interpreted as "AND".
	DefinedTagEquals pulumi.StringArrayInput `pulumi:"definedTagEquals"`
	// A list of tag existence filters to apply.  Only entities for which the specified defined tags exist will be returned. Each item in the list has the format "{namespace}.{tagName}.true" (for checking existence of a defined tag) or "{namespace}.true".  All inputs are case-insensitive. Currently, only existence ("true" at the end) is supported. Absence ("false" at the end) is not supported. Multiple values for the same key (i.e. same namespace and tag name) are interpreted as "OR". Values for different keys (i.e. different namespaces, different tag names, or both) are interpreted as "AND".
	DefinedTagExists pulumi.StringArrayInput `pulumi:"definedTagExists"`
	// A filter to return only log analytics entities whose entityTypeName matches the entire log analytics entity type name of one of the entityTypeNames given in the list. The match is case-insensitive.
	EntityTypeNames pulumi.StringArrayInput                 `pulumi:"entityTypeNames"`
	Filters         GetLogAnalyticsEntitiesFilterArrayInput `pulumi:"filters"`
	// A list of tag filters to apply.  Only entities with a freeform tag matching the value will be returned. The key for each tag is "{tagName}.{value}".  All inputs are case-insensitive. Multiple values for the same tag name are interpreted as "OR".  Values for different tag names are interpreted as "AND".
	FreeformTagEquals pulumi.StringArrayInput `pulumi:"freeformTagEquals"`
	// A list of tag existence filters to apply.  Only entities for which the specified freeform tags exist the value will be returned. The key for each tag is "{tagName}.true".  All inputs are case-insensitive. Currently, only existence ("true" at the end) is supported. Absence ("false" at the end) is not supported. Multiple values for different tag names are interpreted as "AND".
	FreeformTagExists pulumi.StringArrayInput `pulumi:"freeformTagExists"`
	// A filter to return only log analytics entities whose hostname matches the entire hostname given.
	Hostname pulumi.StringPtrInput `pulumi:"hostname"`
	// A filter to return only log analytics entities whose hostname contains the substring given. The match is case-insensitive.
	HostnameContains pulumi.StringPtrInput `pulumi:"hostnameContains"`
	// A filter to return only those log analytics entities whose managementAgentId is null or is not null.
	IsManagementAgentIdNull pulumi.StringPtrInput `pulumi:"isManagementAgentIdNull"`
	// Option to return count of associated log sources for log analytics entity(s).
	IsShowAssociatedSourcesCount pulumi.BoolPtrInput `pulumi:"isShowAssociatedSourcesCount"`
	// A filter to return only log analytics entities whose lifecycleDetails contains the specified string.
	LifecycleDetailsContains pulumi.StringPtrInput `pulumi:"lifecycleDetailsContains"`
	// A filter to return only log analytics entities whose metadata name, value and type matches the specified string. Each item in the array has the format "{name}:{value}:{type}".  All inputs are case-insensitive.
	MetadataEquals pulumi.StringArrayInput `pulumi:"metadataEquals"`
	// A filter to return only log analytics entities whose name matches the entire name given. The match is case-insensitive.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// A filter to return only log analytics entities whose name contains the name given. The match is case-insensitive.
	NameContains pulumi.StringPtrInput `pulumi:"nameContains"`
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringInput `pulumi:"namespace"`
	// A filter to return only log analytics entities whose sourceId matches the sourceId given.
	SourceId pulumi.StringPtrInput `pulumi:"sourceId"`
	// A filter to return only those log analytics entities with the specified lifecycle state. The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetLogAnalyticsEntitiesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetLogAnalyticsEntitiesArgs)(nil)).Elem()
}

// A collection of values returned by getLogAnalyticsEntities.
type GetLogAnalyticsEntitiesResultOutput struct{ *pulumi.OutputState }

func (GetLogAnalyticsEntitiesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetLogAnalyticsEntitiesResult)(nil)).Elem()
}

func (o GetLogAnalyticsEntitiesResultOutput) ToGetLogAnalyticsEntitiesResultOutput() GetLogAnalyticsEntitiesResultOutput {
	return o
}

func (o GetLogAnalyticsEntitiesResultOutput) ToGetLogAnalyticsEntitiesResultOutputWithContext(ctx context.Context) GetLogAnalyticsEntitiesResultOutput {
	return o
}

// The OCID of the Cloud resource which this entity is a representation of. This may be blank when the entity represents a non-cloud resource that the customer may have on their premises.
func (o GetLogAnalyticsEntitiesResultOutput) CloudResourceId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) *string { return v.CloudResourceId }).(pulumi.StringPtrOutput)
}

// Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
func (o GetLogAnalyticsEntitiesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetLogAnalyticsEntitiesResultOutput) DefinedTagEquals() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) []string { return v.DefinedTagEquals }).(pulumi.StringArrayOutput)
}

func (o GetLogAnalyticsEntitiesResultOutput) DefinedTagExists() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) []string { return v.DefinedTagExists }).(pulumi.StringArrayOutput)
}

// Log analytics entity type name.
func (o GetLogAnalyticsEntitiesResultOutput) EntityTypeNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) []string { return v.EntityTypeNames }).(pulumi.StringArrayOutput)
}

func (o GetLogAnalyticsEntitiesResultOutput) Filters() GetLogAnalyticsEntitiesFilterArrayOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) []GetLogAnalyticsEntitiesFilter { return v.Filters }).(GetLogAnalyticsEntitiesFilterArrayOutput)
}

func (o GetLogAnalyticsEntitiesResultOutput) FreeformTagEquals() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) []string { return v.FreeformTagEquals }).(pulumi.StringArrayOutput)
}

func (o GetLogAnalyticsEntitiesResultOutput) FreeformTagExists() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) []string { return v.FreeformTagExists }).(pulumi.StringArrayOutput)
}

// The hostname where the entity represented here is actually present. This would be the output one would get if they run `echo $HOSTNAME` on Linux or an equivalent OS command. This may be different from management agents host since logs may be collected remotely.
func (o GetLogAnalyticsEntitiesResultOutput) Hostname() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) *string { return v.Hostname }).(pulumi.StringPtrOutput)
}

func (o GetLogAnalyticsEntitiesResultOutput) HostnameContains() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) *string { return v.HostnameContains }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetLogAnalyticsEntitiesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetLogAnalyticsEntitiesResultOutput) IsManagementAgentIdNull() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) *string { return v.IsManagementAgentIdNull }).(pulumi.StringPtrOutput)
}

func (o GetLogAnalyticsEntitiesResultOutput) IsShowAssociatedSourcesCount() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) *bool { return v.IsShowAssociatedSourcesCount }).(pulumi.BoolPtrOutput)
}

func (o GetLogAnalyticsEntitiesResultOutput) LifecycleDetailsContains() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) *string { return v.LifecycleDetailsContains }).(pulumi.StringPtrOutput)
}

// The list of log_analytics_entity_collection.
func (o GetLogAnalyticsEntitiesResultOutput) LogAnalyticsEntityCollections() GetLogAnalyticsEntitiesLogAnalyticsEntityCollectionArrayOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) []GetLogAnalyticsEntitiesLogAnalyticsEntityCollection {
		return v.LogAnalyticsEntityCollections
	}).(GetLogAnalyticsEntitiesLogAnalyticsEntityCollectionArrayOutput)
}

func (o GetLogAnalyticsEntitiesResultOutput) MetadataEquals() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) []string { return v.MetadataEquals }).(pulumi.StringArrayOutput)
}

// Log analytics entity name.
func (o GetLogAnalyticsEntitiesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

func (o GetLogAnalyticsEntitiesResultOutput) NameContains() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) *string { return v.NameContains }).(pulumi.StringPtrOutput)
}

func (o GetLogAnalyticsEntitiesResultOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) string { return v.Namespace }).(pulumi.StringOutput)
}

// This indicates the type of source. It is primarily for Enterprise Manager Repository ID.
func (o GetLogAnalyticsEntitiesResultOutput) SourceId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) *string { return v.SourceId }).(pulumi.StringPtrOutput)
}

// The current state of the log analytics entity.
func (o GetLogAnalyticsEntitiesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetLogAnalyticsEntitiesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetLogAnalyticsEntitiesResultOutput{})
}
