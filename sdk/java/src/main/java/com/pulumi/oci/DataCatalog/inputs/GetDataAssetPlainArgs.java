// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataCatalog.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDataAssetPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDataAssetPlainArgs Empty = new GetDataAssetPlainArgs();

    /**
     * Unique catalog identifier.
     * 
     */
    @Import(name="catalogId", required=true)
    private String catalogId;

    /**
     * @return Unique catalog identifier.
     * 
     */
    public String catalogId() {
        return this.catalogId;
    }

    /**
     * Unique data asset key.
     * 
     */
    @Import(name="dataAssetKey", required=true)
    private String dataAssetKey;

    /**
     * @return Unique data asset key.
     * 
     */
    public String dataAssetKey() {
        return this.dataAssetKey;
    }

    /**
     * Specifies the fields to return in a data asset response.
     * 
     */
    @Import(name="fields")
    private @Nullable List<String> fields;

    /**
     * @return Specifies the fields to return in a data asset response.
     * 
     */
    public Optional<List<String>> fields() {
        return Optional.ofNullable(this.fields);
    }

    private GetDataAssetPlainArgs() {}

    private GetDataAssetPlainArgs(GetDataAssetPlainArgs $) {
        this.catalogId = $.catalogId;
        this.dataAssetKey = $.dataAssetKey;
        this.fields = $.fields;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDataAssetPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDataAssetPlainArgs $;

        public Builder() {
            $ = new GetDataAssetPlainArgs();
        }

        public Builder(GetDataAssetPlainArgs defaults) {
            $ = new GetDataAssetPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param catalogId Unique catalog identifier.
         * 
         * @return builder
         * 
         */
        public Builder catalogId(String catalogId) {
            $.catalogId = catalogId;
            return this;
        }

        /**
         * @param dataAssetKey Unique data asset key.
         * 
         * @return builder
         * 
         */
        public Builder dataAssetKey(String dataAssetKey) {
            $.dataAssetKey = dataAssetKey;
            return this;
        }

        /**
         * @param fields Specifies the fields to return in a data asset response.
         * 
         * @return builder
         * 
         */
        public Builder fields(@Nullable List<String> fields) {
            $.fields = fields;
            return this;
        }

        /**
         * @param fields Specifies the fields to return in a data asset response.
         * 
         * @return builder
         * 
         */
        public Builder fields(String... fields) {
            return fields(List.of(fields));
        }

        public GetDataAssetPlainArgs build() {
            $.catalogId = Objects.requireNonNull($.catalogId, "expected parameter 'catalogId' to be non-null");
            $.dataAssetKey = Objects.requireNonNull($.dataAssetKey, "expected parameter 'dataAssetKey' to be non-null");
            return $;
        }
    }

}