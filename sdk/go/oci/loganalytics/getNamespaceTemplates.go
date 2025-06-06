// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loganalytics

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Namespace Templates in Oracle Cloud Infrastructure Log Analytics service.
//
// Returns a list of templates, containing detailed information about them. You may limit the number of results, provide sorting order, and filter by information such as template name, type, display name and description.
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
//			_, err := loganalytics.GetNamespaceTemplates(ctx, &loganalytics.GetNamespaceTemplatesArgs{
//				CompartmentId:           compartmentId,
//				Namespace:               namespaceTemplateNamespace,
//				Name:                    pulumi.StringRef(namespaceTemplateName),
//				NamespaceTemplateFilter: pulumi.StringRef(namespaceTemplateNamespaceTemplateFilter),
//				State:                   pulumi.StringRef(namespaceTemplateState),
//				TemplateDisplayText:     pulumi.StringRef(namespaceTemplateTemplateDisplayText),
//				Type:                    pulumi.StringRef(namespaceTemplateType),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetNamespaceTemplates(ctx *pulumi.Context, args *GetNamespaceTemplatesArgs, opts ...pulumi.InvokeOption) (*GetNamespaceTemplatesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetNamespaceTemplatesResult
	err := ctx.Invoke("oci:LogAnalytics/getNamespaceTemplates:getNamespaceTemplates", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNamespaceTemplates.
type GetNamespaceTemplatesArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string                        `pulumi:"compartmentId"`
	Filters       []GetNamespaceTemplatesFilter `pulumi:"filters"`
	// The template name used for filtering.
	Name *string `pulumi:"name"`
	// The Logging Analytics namespace used for the request.
	Namespace string `pulumi:"namespace"`
	// filter
	NamespaceTemplateFilter *string `pulumi:"namespaceTemplateFilter"`
	// The template lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
	State *string `pulumi:"state"`
	// The template display text used for filtering. Only templates with the specified name or description will be returned.
	TemplateDisplayText *string `pulumi:"templateDisplayText"`
	// The template type used for filtering. Only templates of the specified type will be returned.
	Type *string `pulumi:"type"`
}

// A collection of values returned by getNamespaceTemplates.
type GetNamespaceTemplatesResult struct {
	// Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string                        `pulumi:"compartmentId"`
	Filters       []GetNamespaceTemplatesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of log_analytics_template_collection.
	LogAnalyticsTemplateCollections []GetNamespaceTemplatesLogAnalyticsTemplateCollection `pulumi:"logAnalyticsTemplateCollections"`
	// The template name.
	Name                    *string `pulumi:"name"`
	Namespace               string  `pulumi:"namespace"`
	NamespaceTemplateFilter *string `pulumi:"namespaceTemplateFilter"`
	// The current state of the template.
	State               *string `pulumi:"state"`
	TemplateDisplayText *string `pulumi:"templateDisplayText"`
	// The template type.
	Type *string `pulumi:"type"`
}

func GetNamespaceTemplatesOutput(ctx *pulumi.Context, args GetNamespaceTemplatesOutputArgs, opts ...pulumi.InvokeOption) GetNamespaceTemplatesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetNamespaceTemplatesResultOutput, error) {
			args := v.(GetNamespaceTemplatesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:LogAnalytics/getNamespaceTemplates:getNamespaceTemplates", args, GetNamespaceTemplatesResultOutput{}, options).(GetNamespaceTemplatesResultOutput), nil
		}).(GetNamespaceTemplatesResultOutput)
}

// A collection of arguments for invoking getNamespaceTemplates.
type GetNamespaceTemplatesOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput                    `pulumi:"compartmentId"`
	Filters       GetNamespaceTemplatesFilterArrayInput `pulumi:"filters"`
	// The template name used for filtering.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringInput `pulumi:"namespace"`
	// filter
	NamespaceTemplateFilter pulumi.StringPtrInput `pulumi:"namespaceTemplateFilter"`
	// The template lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
	State pulumi.StringPtrInput `pulumi:"state"`
	// The template display text used for filtering. Only templates with the specified name or description will be returned.
	TemplateDisplayText pulumi.StringPtrInput `pulumi:"templateDisplayText"`
	// The template type used for filtering. Only templates of the specified type will be returned.
	Type pulumi.StringPtrInput `pulumi:"type"`
}

func (GetNamespaceTemplatesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNamespaceTemplatesArgs)(nil)).Elem()
}

// A collection of values returned by getNamespaceTemplates.
type GetNamespaceTemplatesResultOutput struct{ *pulumi.OutputState }

func (GetNamespaceTemplatesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNamespaceTemplatesResult)(nil)).Elem()
}

func (o GetNamespaceTemplatesResultOutput) ToGetNamespaceTemplatesResultOutput() GetNamespaceTemplatesResultOutput {
	return o
}

func (o GetNamespaceTemplatesResultOutput) ToGetNamespaceTemplatesResultOutputWithContext(ctx context.Context) GetNamespaceTemplatesResultOutput {
	return o
}

// Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
func (o GetNamespaceTemplatesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetNamespaceTemplatesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetNamespaceTemplatesResultOutput) Filters() GetNamespaceTemplatesFilterArrayOutput {
	return o.ApplyT(func(v GetNamespaceTemplatesResult) []GetNamespaceTemplatesFilter { return v.Filters }).(GetNamespaceTemplatesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetNamespaceTemplatesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetNamespaceTemplatesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of log_analytics_template_collection.
func (o GetNamespaceTemplatesResultOutput) LogAnalyticsTemplateCollections() GetNamespaceTemplatesLogAnalyticsTemplateCollectionArrayOutput {
	return o.ApplyT(func(v GetNamespaceTemplatesResult) []GetNamespaceTemplatesLogAnalyticsTemplateCollection {
		return v.LogAnalyticsTemplateCollections
	}).(GetNamespaceTemplatesLogAnalyticsTemplateCollectionArrayOutput)
}

// The template name.
func (o GetNamespaceTemplatesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetNamespaceTemplatesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

func (o GetNamespaceTemplatesResultOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v GetNamespaceTemplatesResult) string { return v.Namespace }).(pulumi.StringOutput)
}

func (o GetNamespaceTemplatesResultOutput) NamespaceTemplateFilter() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetNamespaceTemplatesResult) *string { return v.NamespaceTemplateFilter }).(pulumi.StringPtrOutput)
}

// The current state of the template.
func (o GetNamespaceTemplatesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetNamespaceTemplatesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func (o GetNamespaceTemplatesResultOutput) TemplateDisplayText() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetNamespaceTemplatesResult) *string { return v.TemplateDisplayText }).(pulumi.StringPtrOutput)
}

// The template type.
func (o GetNamespaceTemplatesResultOutput) Type() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetNamespaceTemplatesResult) *string { return v.Type }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetNamespaceTemplatesResultOutput{})
}
