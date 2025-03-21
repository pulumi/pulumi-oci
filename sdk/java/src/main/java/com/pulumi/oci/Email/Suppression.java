// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Email;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Email.SuppressionArgs;
import com.pulumi.oci.Email.inputs.SuppressionState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Suppression resource in Oracle Cloud Infrastructure Email service.
 * 
 * Adds recipient email addresses to the suppression list for a tenancy.
 * Addresses added to the suppression list via the API are denoted as
 * &#34;MANUAL&#34; in the `reason` field. *Note:* All email addresses added to the
 * suppression list are normalized to include only lowercase letters.
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
 * import com.pulumi.oci.Email.Suppression;
 * import com.pulumi.oci.Email.SuppressionArgs;
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
 *         var testSuppression = new Suppression("testSuppression", SuppressionArgs.builder()
 *             .compartmentId(tenancyOcid)
 *             .emailAddress(suppressionEmailAddress)
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
 * Suppressions can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Email/suppression:Suppression test_suppression &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Email/suppression:Suppression")
public class Suppression extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The recipient email address of the suppression.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="emailAddress", refs={String.class}, tree="[0]")
    private Output<String> emailAddress;

    /**
     * @return The recipient email address of the suppression.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> emailAddress() {
        return this.emailAddress;
    }
    /**
     * The specific error message returned by a system that resulted in the suppression. This message is usually an SMTP error code with additional descriptive text. Not provided for all types of suppressions.
     * 
     */
    @Export(name="errorDetail", refs={String.class}, tree="[0]")
    private Output<String> errorDetail;

    /**
     * @return The specific error message returned by a system that resulted in the suppression. This message is usually an SMTP error code with additional descriptive text. Not provided for all types of suppressions.
     * 
     */
    public Output<String> errorDetail() {
        return this.errorDetail;
    }
    /**
     * DNS name of the source of the error that caused the suppression. Will be set to either the remote-mta or reporting-mta field from a delivery status notification (RFC 3464) when available. Not provided for all types of suppressions, and not always known.
     * 
     */
    @Export(name="errorSource", refs={String.class}, tree="[0]")
    private Output<String> errorSource;

    /**
     * @return DNS name of the source of the error that caused the suppression. Will be set to either the remote-mta or reporting-mta field from a delivery status notification (RFC 3464) when available. Not provided for all types of suppressions, and not always known.
     * 
     */
    public Output<String> errorSource() {
        return this.errorSource;
    }
    /**
     * The value of the Message-ID header from the email that triggered a suppression. This value is as defined in RFC 5322 section 3.6.4, excluding angle-brackets. Not provided for all types of suppressions.
     * 
     */
    @Export(name="messageId", refs={String.class}, tree="[0]")
    private Output<String> messageId;

    /**
     * @return The value of the Message-ID header from the email that triggered a suppression. This value is as defined in RFC 5322 section 3.6.4, excluding angle-brackets. Not provided for all types of suppressions.
     * 
     */
    public Output<String> messageId() {
        return this.messageId;
    }
    /**
     * The reason that the email address was suppressed. For more information on the types of bounces, see [Suppression List](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
     * 
     */
    @Export(name="reason", refs={String.class}, tree="[0]")
    private Output<String> reason;

    /**
     * @return The reason that the email address was suppressed. For more information on the types of bounces, see [Suppression List](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
     * 
     */
    public Output<String> reason() {
        return this.reason;
    }
    /**
     * The date and time a recipient&#39;s email address was added to the suppression list, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time a recipient&#39;s email address was added to the suppression list, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The last date and time the suppression prevented submission in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Export(name="timeLastSuppressed", refs={String.class}, tree="[0]")
    private Output<String> timeLastSuppressed;

    /**
     * @return The last date and time the suppression prevented submission in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Output<String> timeLastSuppressed() {
        return this.timeLastSuppressed;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Suppression(java.lang.String name) {
        this(name, SuppressionArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Suppression(java.lang.String name, SuppressionArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Suppression(java.lang.String name, SuppressionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Email/suppression:Suppression", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private Suppression(java.lang.String name, Output<java.lang.String> id, @Nullable SuppressionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Email/suppression:Suppression", name, state, makeResourceOptions(options, id), false);
    }

    private static SuppressionArgs makeArgs(SuppressionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? SuppressionArgs.Empty : args;
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
    public static Suppression get(java.lang.String name, Output<java.lang.String> id, @Nullable SuppressionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Suppression(name, id, state, options);
    }
}
