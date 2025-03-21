// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetMigrationAssetPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMigrationAssetPlainArgs Empty = new GetMigrationAssetPlainArgs();

    /**
     * Unique migration asset identifier
     * 
     */
    @Import(name="migrationAssetId", required=true)
    private String migrationAssetId;

    /**
     * @return Unique migration asset identifier
     * 
     */
    public String migrationAssetId() {
        return this.migrationAssetId;
    }

    private GetMigrationAssetPlainArgs() {}

    private GetMigrationAssetPlainArgs(GetMigrationAssetPlainArgs $) {
        this.migrationAssetId = $.migrationAssetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMigrationAssetPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMigrationAssetPlainArgs $;

        public Builder() {
            $ = new GetMigrationAssetPlainArgs();
        }

        public Builder(GetMigrationAssetPlainArgs defaults) {
            $ = new GetMigrationAssetPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param migrationAssetId Unique migration asset identifier
         * 
         * @return builder
         * 
         */
        public Builder migrationAssetId(String migrationAssetId) {
            $.migrationAssetId = migrationAssetId;
            return this;
        }

        public GetMigrationAssetPlainArgs build() {
            if ($.migrationAssetId == null) {
                throw new MissingRequiredPropertyException("GetMigrationAssetPlainArgs", "migrationAssetId");
            }
            return $;
        }
    }

}
