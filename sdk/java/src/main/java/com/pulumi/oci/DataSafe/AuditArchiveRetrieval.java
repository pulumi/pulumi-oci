// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DataSafe.AuditArchiveRetrievalArgs;
import com.pulumi.oci.DataSafe.inputs.AuditArchiveRetrievalState;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Audit Archive Retrieval resource in Oracle Cloud Infrastructure Data Safe service.
 * 
 * Creates a work request to retrieve archived audit data. This asynchronous process will usually take over an hour to complete.
 * Save the id from the response of this operation. Call GetAuditArchiveRetrieval operation after an hour, passing the id to know the status of
 * this operation.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * AuditArchiveRetrievals can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:DataSafe/auditArchiveRetrieval:AuditArchiveRetrieval test_audit_archive_retrieval &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DataSafe/auditArchiveRetrieval:AuditArchiveRetrieval")
public class AuditArchiveRetrieval extends com.pulumi.resources.CustomResource {
    /**
     * Total count of audit events to be retrieved from the archive for the specified date range.
     * 
     */
    @Export(name="auditEventCount", type=String.class, parameters={})
    private Output<String> auditEventCount;

    /**
     * @return Total count of audit events to be retrieved from the archive for the specified date range.
     * 
     */
    public Output<String> auditEventCount() {
        return this.auditEventCount;
    }
    /**
     * (Updatable) The OCID of the compartment that contains the archival retrieval.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that contains the archival retrieval.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Description of the archive retrieval.
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) Description of the archive retrieval.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) The display name of the archive retrieval. The name does not have to be unique, and is changeable.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) The display name of the archive retrieval. The name does not have to be unique, and is changeable.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * End month of the archive retrieval, in the format defined by RFC3339.
     * 
     */
    @Export(name="endDate", type=String.class, parameters={})
    private Output<String> endDate;

    /**
     * @return End month of the archive retrieval, in the format defined by RFC3339.
     * 
     */
    public Output<String> endDate() {
        return this.endDate;
    }
    /**
     * The Error details of a failed archive retrieval.
     * 
     */
    @Export(name="errorInfo", type=String.class, parameters={})
    private Output<String> errorInfo;

    /**
     * @return The Error details of a failed archive retrieval.
     * 
     */
    public Output<String> errorInfo() {
        return this.errorInfo;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * Details about the current state of the archive retrieval.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return Details about the current state of the archive retrieval.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * Start month of the archive retrieval, in the format defined by RFC3339.
     * 
     */
    @Export(name="startDate", type=String.class, parameters={})
    private Output<String> startDate;

    /**
     * @return Start month of the archive retrieval, in the format defined by RFC3339.
     * 
     */
    public Output<String> startDate() {
        return this.startDate;
    }
    /**
     * The current state of the archive retrieval.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the archive retrieval.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * The OCID of the target associated with the archive retrieval.
     * 
     */
    @Export(name="targetId", type=String.class, parameters={})
    private Output<String> targetId;

    /**
     * @return The OCID of the target associated with the archive retrieval.
     * 
     */
    public Output<String> targetId() {
        return this.targetId;
    }
    /**
     * The date time when archive retrieval request was fulfilled, in the format defined by RFC3339.
     * 
     */
    @Export(name="timeCompleted", type=String.class, parameters={})
    private Output<String> timeCompleted;

    /**
     * @return The date time when archive retrieval request was fulfilled, in the format defined by RFC3339.
     * 
     */
    public Output<String> timeCompleted() {
        return this.timeCompleted;
    }
    /**
     * The date time when retrieved archive data will be deleted from Data Safe and unloaded back into archival.
     * 
     */
    @Export(name="timeOfExpiry", type=String.class, parameters={})
    private Output<String> timeOfExpiry;

    /**
     * @return The date time when retrieved archive data will be deleted from Data Safe and unloaded back into archival.
     * 
     */
    public Output<String> timeOfExpiry() {
        return this.timeOfExpiry;
    }
    /**
     * The date time when archive retrieval was requested, in the format defined by RFC3339.
     * 
     */
    @Export(name="timeRequested", type=String.class, parameters={})
    private Output<String> timeRequested;

    /**
     * @return The date time when archive retrieval was requested, in the format defined by RFC3339.
     * 
     */
    public Output<String> timeRequested() {
        return this.timeRequested;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public AuditArchiveRetrieval(String name) {
        this(name, AuditArchiveRetrievalArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public AuditArchiveRetrieval(String name, AuditArchiveRetrievalArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public AuditArchiveRetrieval(String name, AuditArchiveRetrievalArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataSafe/auditArchiveRetrieval:AuditArchiveRetrieval", name, args == null ? AuditArchiveRetrievalArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private AuditArchiveRetrieval(String name, Output<String> id, @Nullable AuditArchiveRetrievalState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataSafe/auditArchiveRetrieval:AuditArchiveRetrieval", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static AuditArchiveRetrieval get(String name, Output<String> id, @Nullable AuditArchiveRetrievalState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new AuditArchiveRetrieval(name, id, state, options);
    }
}
