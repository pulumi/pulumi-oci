// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudMigrations.inputs.GetMigrationAssetsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetMigrationAssetsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMigrationAssetsPlainArgs Empty = new GetMigrationAssetsPlainArgs();

    /**
     * A filter to return only resources that match the entire given display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire given display name.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetMigrationAssetsFilter> filters;

    public Optional<List<GetMigrationAssetsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique migration asset identifier
     * 
     */
    @Import(name="migrationAssetId")
    private @Nullable String migrationAssetId;

    /**
     * @return Unique migration asset identifier
     * 
     */
    public Optional<String> migrationAssetId() {
        return Optional.ofNullable(this.migrationAssetId);
    }

    /**
     * Unique migration identifier
     * 
     */
    @Import(name="migrationId")
    private @Nullable String migrationId;

    /**
     * @return Unique migration identifier
     * 
     */
    public Optional<String> migrationId() {
        return Optional.ofNullable(this.migrationId);
    }

    /**
     * The current state of the migration asset.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The current state of the migration asset.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetMigrationAssetsPlainArgs() {}

    private GetMigrationAssetsPlainArgs(GetMigrationAssetsPlainArgs $) {
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.migrationAssetId = $.migrationAssetId;
        this.migrationId = $.migrationId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMigrationAssetsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMigrationAssetsPlainArgs $;

        public Builder() {
            $ = new GetMigrationAssetsPlainArgs();
        }

        public Builder(GetMigrationAssetsPlainArgs defaults) {
            $ = new GetMigrationAssetsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName A filter to return only resources that match the entire given display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetMigrationAssetsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetMigrationAssetsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param migrationAssetId Unique migration asset identifier
         * 
         * @return builder
         * 
         */
        public Builder migrationAssetId(@Nullable String migrationAssetId) {
            $.migrationAssetId = migrationAssetId;
            return this;
        }

        /**
         * @param migrationId Unique migration identifier
         * 
         * @return builder
         * 
         */
        public Builder migrationId(@Nullable String migrationId) {
            $.migrationId = migrationId;
            return this;
        }

        /**
         * @param state The current state of the migration asset.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetMigrationAssetsPlainArgs build() {
            return $;
        }
    }

}
