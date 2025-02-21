// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class JavaDownloadsJavaLicenseAcceptanceRecordLastUpdatedByArgs extends com.pulumi.resources.ResourceArgs {

    public static final JavaDownloadsJavaLicenseAcceptanceRecordLastUpdatedByArgs Empty = new JavaDownloadsJavaLicenseAcceptanceRecordLastUpdatedByArgs();

    /**
     * The name of the principal.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The name of the principal.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The email of the principal.
     * 
     */
    @Import(name="email")
    private @Nullable Output<String> email;

    /**
     * @return The email of the principal.
     * 
     */
    public Optional<Output<String>> email() {
        return Optional.ofNullable(this.email);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the principal.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the principal.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    private JavaDownloadsJavaLicenseAcceptanceRecordLastUpdatedByArgs() {}

    private JavaDownloadsJavaLicenseAcceptanceRecordLastUpdatedByArgs(JavaDownloadsJavaLicenseAcceptanceRecordLastUpdatedByArgs $) {
        this.displayName = $.displayName;
        this.email = $.email;
        this.id = $.id;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(JavaDownloadsJavaLicenseAcceptanceRecordLastUpdatedByArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private JavaDownloadsJavaLicenseAcceptanceRecordLastUpdatedByArgs $;

        public Builder() {
            $ = new JavaDownloadsJavaLicenseAcceptanceRecordLastUpdatedByArgs();
        }

        public Builder(JavaDownloadsJavaLicenseAcceptanceRecordLastUpdatedByArgs defaults) {
            $ = new JavaDownloadsJavaLicenseAcceptanceRecordLastUpdatedByArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName The name of the principal.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The name of the principal.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param email The email of the principal.
         * 
         * @return builder
         * 
         */
        public Builder email(@Nullable Output<String> email) {
            $.email = email;
            return this;
        }

        /**
         * @param email The email of the principal.
         * 
         * @return builder
         * 
         */
        public Builder email(String email) {
            return email(Output.of(email));
        }

        /**
         * @param id The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the principal.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the principal.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        public JavaDownloadsJavaLicenseAcceptanceRecordLastUpdatedByArgs build() {
            return $;
        }
    }

}
