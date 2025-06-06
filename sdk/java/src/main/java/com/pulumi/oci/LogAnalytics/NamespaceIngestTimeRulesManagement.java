// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.LogAnalytics.NamespaceIngestTimeRulesManagementArgs;
import com.pulumi.oci.LogAnalytics.inputs.NamespaceIngestTimeRulesManagementState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Namespace Ingest Time Rules Management resource in Oracle Cloud Infrastructure Log Analytics service.
 * 
 * Enables the specified ingest time rule.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.LogAnalytics.NamespaceIngestTimeRulesManagement;
 * import com.pulumi.oci.LogAnalytics.NamespaceIngestTimeRulesManagementArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testNamespaceIngestTimeRulesManagement = new NamespaceIngestTimeRulesManagement("testNamespaceIngestTimeRulesManagement", NamespaceIngestTimeRulesManagementArgs.builder()
 *             .ingestTimeRuleId(testRule.id())
 *             .namespace(namespaceIngestTimeRulesManagementNamespace)
 *             .enableIngestTimeRule(enableIngestTimeRule)
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 */
@ResourceType(type="oci:LogAnalytics/namespaceIngestTimeRulesManagement:NamespaceIngestTimeRulesManagement")
public class NamespaceIngestTimeRulesManagement extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="enableIngestTimeRule", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> enableIngestTimeRule;

    /**
     * @return (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Boolean> enableIngestTimeRule() {
        return this.enableIngestTimeRule;
    }
    /**
     * Unique ocid of the ingest time rule.
     * 
     */
    @Export(name="ingestTimeRuleId", refs={String.class}, tree="[0]")
    private Output<String> ingestTimeRuleId;

    /**
     * @return Unique ocid of the ingest time rule.
     * 
     */
    public Output<String> ingestTimeRuleId() {
        return this.ingestTimeRuleId;
    }
    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Export(name="namespace", refs={String.class}, tree="[0]")
    private Output<String> namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public NamespaceIngestTimeRulesManagement(java.lang.String name) {
        this(name, NamespaceIngestTimeRulesManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public NamespaceIngestTimeRulesManagement(java.lang.String name, NamespaceIngestTimeRulesManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public NamespaceIngestTimeRulesManagement(java.lang.String name, NamespaceIngestTimeRulesManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:LogAnalytics/namespaceIngestTimeRulesManagement:NamespaceIngestTimeRulesManagement", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private NamespaceIngestTimeRulesManagement(java.lang.String name, Output<java.lang.String> id, @Nullable NamespaceIngestTimeRulesManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:LogAnalytics/namespaceIngestTimeRulesManagement:NamespaceIngestTimeRulesManagement", name, state, makeResourceOptions(options, id), false);
    }

    private static NamespaceIngestTimeRulesManagementArgs makeArgs(NamespaceIngestTimeRulesManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? NamespaceIngestTimeRulesManagementArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
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
    public static NamespaceIngestTimeRulesManagement get(java.lang.String name, Output<java.lang.String> id, @Nullable NamespaceIngestTimeRulesManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new NamespaceIngestTimeRulesManagement(name, id, state, options);
    }
}
