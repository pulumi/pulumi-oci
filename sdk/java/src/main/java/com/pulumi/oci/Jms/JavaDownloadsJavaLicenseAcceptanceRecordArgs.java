// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class JavaDownloadsJavaLicenseAcceptanceRecordArgs extends com.pulumi.resources.ResourceArgs {

    public static final JavaDownloadsJavaLicenseAcceptanceRecordArgs Empty = new JavaDownloadsJavaLicenseAcceptanceRecordArgs();

    /**
     * The tenancy [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user accepting the license.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The tenancy [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user accepting the license.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Status of license acceptance.
     * 
     */
    @Import(name="licenseAcceptanceStatus", required=true)
    private Output<String> licenseAcceptanceStatus;

    /**
     * @return (Updatable) Status of license acceptance.
     * 
     */
    public Output<String> licenseAcceptanceStatus() {
        return this.licenseAcceptanceStatus;
    }

    /**
     * License type for the Java version.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="licenseType", required=true)
    private Output<String> licenseType;

    /**
     * @return License type for the Java version.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> licenseType() {
        return this.licenseType;
    }

    private JavaDownloadsJavaLicenseAcceptanceRecordArgs() {}

    private JavaDownloadsJavaLicenseAcceptanceRecordArgs(JavaDownloadsJavaLicenseAcceptanceRecordArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.licenseAcceptanceStatus = $.licenseAcceptanceStatus;
        this.licenseType = $.licenseType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(JavaDownloadsJavaLicenseAcceptanceRecordArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private JavaDownloadsJavaLicenseAcceptanceRecordArgs $;

        public Builder() {
            $ = new JavaDownloadsJavaLicenseAcceptanceRecordArgs();
        }

        public Builder(JavaDownloadsJavaLicenseAcceptanceRecordArgs defaults) {
            $ = new JavaDownloadsJavaLicenseAcceptanceRecordArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The tenancy [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user accepting the license.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The tenancy [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user accepting the license.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param licenseAcceptanceStatus (Updatable) Status of license acceptance.
         * 
         * @return builder
         * 
         */
        public Builder licenseAcceptanceStatus(Output<String> licenseAcceptanceStatus) {
            $.licenseAcceptanceStatus = licenseAcceptanceStatus;
            return this;
        }

        /**
         * @param licenseAcceptanceStatus (Updatable) Status of license acceptance.
         * 
         * @return builder
         * 
         */
        public Builder licenseAcceptanceStatus(String licenseAcceptanceStatus) {
            return licenseAcceptanceStatus(Output.of(licenseAcceptanceStatus));
        }

        /**
         * @param licenseType License type for the Java version.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder licenseType(Output<String> licenseType) {
            $.licenseType = licenseType;
            return this;
        }

        /**
         * @param licenseType License type for the Java version.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder licenseType(String licenseType) {
            return licenseType(Output.of(licenseType));
        }

        public JavaDownloadsJavaLicenseAcceptanceRecordArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("JavaDownloadsJavaLicenseAcceptanceRecordArgs", "compartmentId");
            }
            if ($.licenseAcceptanceStatus == null) {
                throw new MissingRequiredPropertyException("JavaDownloadsJavaLicenseAcceptanceRecordArgs", "licenseAcceptanceStatus");
            }
            if ($.licenseType == null) {
                throw new MissingRequiredPropertyException("JavaDownloadsJavaLicenseAcceptanceRecordArgs", "licenseType");
            }
            return $;
        }
    }

}
