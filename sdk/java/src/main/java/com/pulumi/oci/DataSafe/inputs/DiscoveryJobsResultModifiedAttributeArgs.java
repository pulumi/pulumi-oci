// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DiscoveryJobsResultModifiedAttributeArgs extends com.pulumi.resources.ResourceArgs {

    public static final DiscoveryJobsResultModifiedAttributeArgs Empty = new DiscoveryJobsResultModifiedAttributeArgs();

    /**
     * Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
     * 
     */
    @Import(name="appDefinedChildColumnKeys")
    private @Nullable Output<List<String>> appDefinedChildColumnKeys;

    /**
     * @return Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
     * 
     */
    public Optional<Output<List<String>>> appDefinedChildColumnKeys() {
        return Optional.ofNullable(this.appDefinedChildColumnKeys);
    }

    /**
     * Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
     * 
     */
    @Import(name="dbDefinedChildColumnKeys")
    private @Nullable Output<List<String>> dbDefinedChildColumnKeys;

    /**
     * @return Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
     * 
     */
    public Optional<Output<List<String>>> dbDefinedChildColumnKeys() {
        return Optional.ofNullable(this.dbDefinedChildColumnKeys);
    }

    private DiscoveryJobsResultModifiedAttributeArgs() {}

    private DiscoveryJobsResultModifiedAttributeArgs(DiscoveryJobsResultModifiedAttributeArgs $) {
        this.appDefinedChildColumnKeys = $.appDefinedChildColumnKeys;
        this.dbDefinedChildColumnKeys = $.dbDefinedChildColumnKeys;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DiscoveryJobsResultModifiedAttributeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DiscoveryJobsResultModifiedAttributeArgs $;

        public Builder() {
            $ = new DiscoveryJobsResultModifiedAttributeArgs();
        }

        public Builder(DiscoveryJobsResultModifiedAttributeArgs defaults) {
            $ = new DiscoveryJobsResultModifiedAttributeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param appDefinedChildColumnKeys Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder appDefinedChildColumnKeys(@Nullable Output<List<String>> appDefinedChildColumnKeys) {
            $.appDefinedChildColumnKeys = appDefinedChildColumnKeys;
            return this;
        }

        /**
         * @param appDefinedChildColumnKeys Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder appDefinedChildColumnKeys(List<String> appDefinedChildColumnKeys) {
            return appDefinedChildColumnKeys(Output.of(appDefinedChildColumnKeys));
        }

        /**
         * @param appDefinedChildColumnKeys Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder appDefinedChildColumnKeys(String... appDefinedChildColumnKeys) {
            return appDefinedChildColumnKeys(List.of(appDefinedChildColumnKeys));
        }

        /**
         * @param dbDefinedChildColumnKeys Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder dbDefinedChildColumnKeys(@Nullable Output<List<String>> dbDefinedChildColumnKeys) {
            $.dbDefinedChildColumnKeys = dbDefinedChildColumnKeys;
            return this;
        }

        /**
         * @param dbDefinedChildColumnKeys Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder dbDefinedChildColumnKeys(List<String> dbDefinedChildColumnKeys) {
            return dbDefinedChildColumnKeys(Output.of(dbDefinedChildColumnKeys));
        }

        /**
         * @param dbDefinedChildColumnKeys Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder dbDefinedChildColumnKeys(String... dbDefinedChildColumnKeys) {
            return dbDefinedChildColumnKeys(List.of(dbDefinedChildColumnKeys));
        }

        public DiscoveryJobsResultModifiedAttributeArgs build() {
            return $;
        }
    }

}
