// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DataSafe.SetSecurityAssessmentBaselineArgs;
import com.pulumi.oci.DataSafe.inputs.SetSecurityAssessmentBaselineState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Set Security Assessment Baseline resource in Oracle Cloud Infrastructure Data Safe service.
 * 
 * Sets the saved security assessment as the baseline in the compartment where the the specified assessment resides. The security assessment needs to be of type &#39;SAVED&#39;.
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
 * import com.pulumi.oci.DataSafe.SetSecurityAssessmentBaseline;
 * import com.pulumi.oci.DataSafe.SetSecurityAssessmentBaselineArgs;
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
 *         var testSetSecurityAssessmentBaseline = new SetSecurityAssessmentBaseline("testSetSecurityAssessmentBaseline", SetSecurityAssessmentBaselineArgs.builder()
 *             .securityAssessmentId(testSecurityAssessment.id())
 *             .assessmentIds(setSecurityAssessmentBaselineAssessmentIds)
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * SetSecurityAssessmentBaseline can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:DataSafe/setSecurityAssessmentBaseline:SetSecurityAssessmentBaseline test_set_security_assessment_baseline &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DataSafe/setSecurityAssessmentBaseline:SetSecurityAssessmentBaseline")
public class SetSecurityAssessmentBaseline extends com.pulumi.resources.CustomResource {
    /**
     * The list of OCIDs for the security assessments that need to be updated while setting the baseline.
     * 
     */
    @Export(name="assessmentIds", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> assessmentIds;

    /**
     * @return The list of OCIDs for the security assessments that need to be updated while setting the baseline.
     * 
     */
    public Output<List<String>> assessmentIds() {
        return this.assessmentIds;
    }
    /**
     * The OCID of the security assessment.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="securityAssessmentId", refs={String.class}, tree="[0]")
    private Output<String> securityAssessmentId;

    /**
     * @return The OCID of the security assessment.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> securityAssessmentId() {
        return this.securityAssessmentId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public SetSecurityAssessmentBaseline(java.lang.String name) {
        this(name, SetSecurityAssessmentBaselineArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public SetSecurityAssessmentBaseline(java.lang.String name, SetSecurityAssessmentBaselineArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public SetSecurityAssessmentBaseline(java.lang.String name, SetSecurityAssessmentBaselineArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataSafe/setSecurityAssessmentBaseline:SetSecurityAssessmentBaseline", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private SetSecurityAssessmentBaseline(java.lang.String name, Output<java.lang.String> id, @Nullable SetSecurityAssessmentBaselineState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataSafe/setSecurityAssessmentBaseline:SetSecurityAssessmentBaseline", name, state, makeResourceOptions(options, id), false);
    }

    private static SetSecurityAssessmentBaselineArgs makeArgs(SetSecurityAssessmentBaselineArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? SetSecurityAssessmentBaselineArgs.Empty : args;
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
    public static SetSecurityAssessmentBaseline get(java.lang.String name, Output<java.lang.String> id, @Nullable SetSecurityAssessmentBaselineState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new SetSecurityAssessmentBaseline(name, id, state, options);
    }
}
