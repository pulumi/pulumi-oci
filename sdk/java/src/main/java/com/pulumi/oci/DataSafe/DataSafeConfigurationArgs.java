// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DataSafeConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final DataSafeConfigurationArgs Empty = new DataSafeConfigurationArgs();

    /**
     * (Updatable) A filter to return only resources that match the specified compartment OCID.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) A filter to return only resources that match the specified compartment OCID.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Indicates if Data Safe is enabled.
     * 
     */
    @Import(name="isEnabled", required=true)
    private Output<Boolean> isEnabled;

    /**
     * @return (Updatable) Indicates if Data Safe is enabled.
     * 
     */
    public Output<Boolean> isEnabled() {
        return this.isEnabled;
    }

    private DataSafeConfigurationArgs() {}

    private DataSafeConfigurationArgs(DataSafeConfigurationArgs $) {
        this.compartmentId = $.compartmentId;
        this.isEnabled = $.isEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DataSafeConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DataSafeConfigurationArgs $;

        public Builder() {
            $ = new DataSafeConfigurationArgs();
        }

        public Builder(DataSafeConfigurationArgs defaults) {
            $ = new DataSafeConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) A filter to return only resources that match the specified compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) A filter to return only resources that match the specified compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param isEnabled (Updatable) Indicates if Data Safe is enabled.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Output<Boolean> isEnabled) {
            $.isEnabled = isEnabled;
            return this;
        }

        /**
         * @param isEnabled (Updatable) Indicates if Data Safe is enabled.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Boolean isEnabled) {
            return isEnabled(Output.of(isEnabled));
        }

        public DataSafeConfigurationArgs build() {
            $.isEnabled = Objects.requireNonNull($.isEnabled, "expected parameter 'isEnabled' to be non-null");
            return $;
        }
    }

}