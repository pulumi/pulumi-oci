// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataConnectivity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataConnectivity.inputs.GetRegistryDataAssetsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRegistryDataAssetsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRegistryDataAssetsArgs Empty = new GetRegistryDataAssetsArgs();

    /**
     * Endpoint Ids used for data-plane APIs to filter or prefer specific endpoint.
     * 
     */
    @Import(name="endpointIds")
    private @Nullable Output<List<String>> endpointIds;

    /**
     * @return Endpoint Ids used for data-plane APIs to filter or prefer specific endpoint.
     * 
     */
    public Optional<Output<List<String>>> endpointIds() {
        return Optional.ofNullable(this.endpointIds);
    }

    /**
     * Endpoints which will be excluded while listing dataAssets
     * 
     */
    @Import(name="excludeEndpointIds")
    private @Nullable Output<List<String>> excludeEndpointIds;

    /**
     * @return Endpoints which will be excluded while listing dataAssets
     * 
     */
    public Optional<Output<List<String>>> excludeEndpointIds() {
        return Optional.ofNullable(this.excludeEndpointIds);
    }

    /**
     * Types which wont be listed while listing dataAsset/Connection
     * 
     */
    @Import(name="excludeTypes")
    private @Nullable Output<List<String>> excludeTypes;

    /**
     * @return Types which wont be listed while listing dataAsset/Connection
     * 
     */
    public Optional<Output<List<String>>> excludeTypes() {
        return Optional.ofNullable(this.excludeTypes);
    }

    /**
     * If value is FAVORITES_ONLY, then only objects marked as favorite by the requesting user will be included in result. If value is NON_FAVORITES_ONLY, then objects marked as favorites by the requesting user will be skipped. If value is ALL or if not specified, all objects, irrespective of favorites or not will be returned. Default is ALL.
     * 
     */
    @Import(name="favoritesQueryParam")
    private @Nullable Output<String> favoritesQueryParam;

    /**
     * @return If value is FAVORITES_ONLY, then only objects marked as favorite by the requesting user will be included in result. If value is NON_FAVORITES_ONLY, then objects marked as favorites by the requesting user will be skipped. If value is ALL or if not specified, all objects, irrespective of favorites or not will be returned. Default is ALL.
     * 
     */
    public Optional<Output<String>> favoritesQueryParam() {
        return Optional.ofNullable(this.favoritesQueryParam);
    }

    /**
     * Specifies the fields to get for an object.
     * 
     */
    @Import(name="fields")
    private @Nullable Output<List<String>> fields;

    /**
     * @return Specifies the fields to get for an object.
     * 
     */
    public Optional<Output<List<String>>> fields() {
        return Optional.ofNullable(this.fields);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetRegistryDataAssetsFilterArgs>> filters;

    public Optional<Output<List<GetRegistryDataAssetsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique key of the folder.
     * 
     */
    @Import(name="folderId")
    private @Nullable Output<String> folderId;

    /**
     * @return Unique key of the folder.
     * 
     */
    public Optional<Output<String>> folderId() {
        return Optional.ofNullable(this.folderId);
    }

    /**
     * DataAsset type which needs to be listed while listing dataAssets
     * 
     */
    @Import(name="includeTypes")
    private @Nullable Output<List<String>> includeTypes;

    /**
     * @return DataAsset type which needs to be listed while listing dataAssets
     * 
     */
    public Optional<Output<List<String>>> includeTypes() {
        return Optional.ofNullable(this.includeTypes);
    }

    /**
     * Used to filter by the name of the object.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Used to filter by the name of the object.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The registry Ocid.
     * 
     */
    @Import(name="registryId", required=true)
    private Output<String> registryId;

    /**
     * @return The registry Ocid.
     * 
     */
    public Output<String> registryId() {
        return this.registryId;
    }

    /**
     * Specific DataAsset Type
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return Specific DataAsset Type
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private GetRegistryDataAssetsArgs() {}

    private GetRegistryDataAssetsArgs(GetRegistryDataAssetsArgs $) {
        this.endpointIds = $.endpointIds;
        this.excludeEndpointIds = $.excludeEndpointIds;
        this.excludeTypes = $.excludeTypes;
        this.favoritesQueryParam = $.favoritesQueryParam;
        this.fields = $.fields;
        this.filters = $.filters;
        this.folderId = $.folderId;
        this.includeTypes = $.includeTypes;
        this.name = $.name;
        this.registryId = $.registryId;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRegistryDataAssetsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRegistryDataAssetsArgs $;

        public Builder() {
            $ = new GetRegistryDataAssetsArgs();
        }

        public Builder(GetRegistryDataAssetsArgs defaults) {
            $ = new GetRegistryDataAssetsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param endpointIds Endpoint Ids used for data-plane APIs to filter or prefer specific endpoint.
         * 
         * @return builder
         * 
         */
        public Builder endpointIds(@Nullable Output<List<String>> endpointIds) {
            $.endpointIds = endpointIds;
            return this;
        }

        /**
         * @param endpointIds Endpoint Ids used for data-plane APIs to filter or prefer specific endpoint.
         * 
         * @return builder
         * 
         */
        public Builder endpointIds(List<String> endpointIds) {
            return endpointIds(Output.of(endpointIds));
        }

        /**
         * @param endpointIds Endpoint Ids used for data-plane APIs to filter or prefer specific endpoint.
         * 
         * @return builder
         * 
         */
        public Builder endpointIds(String... endpointIds) {
            return endpointIds(List.of(endpointIds));
        }

        /**
         * @param excludeEndpointIds Endpoints which will be excluded while listing dataAssets
         * 
         * @return builder
         * 
         */
        public Builder excludeEndpointIds(@Nullable Output<List<String>> excludeEndpointIds) {
            $.excludeEndpointIds = excludeEndpointIds;
            return this;
        }

        /**
         * @param excludeEndpointIds Endpoints which will be excluded while listing dataAssets
         * 
         * @return builder
         * 
         */
        public Builder excludeEndpointIds(List<String> excludeEndpointIds) {
            return excludeEndpointIds(Output.of(excludeEndpointIds));
        }

        /**
         * @param excludeEndpointIds Endpoints which will be excluded while listing dataAssets
         * 
         * @return builder
         * 
         */
        public Builder excludeEndpointIds(String... excludeEndpointIds) {
            return excludeEndpointIds(List.of(excludeEndpointIds));
        }

        /**
         * @param excludeTypes Types which wont be listed while listing dataAsset/Connection
         * 
         * @return builder
         * 
         */
        public Builder excludeTypes(@Nullable Output<List<String>> excludeTypes) {
            $.excludeTypes = excludeTypes;
            return this;
        }

        /**
         * @param excludeTypes Types which wont be listed while listing dataAsset/Connection
         * 
         * @return builder
         * 
         */
        public Builder excludeTypes(List<String> excludeTypes) {
            return excludeTypes(Output.of(excludeTypes));
        }

        /**
         * @param excludeTypes Types which wont be listed while listing dataAsset/Connection
         * 
         * @return builder
         * 
         */
        public Builder excludeTypes(String... excludeTypes) {
            return excludeTypes(List.of(excludeTypes));
        }

        /**
         * @param favoritesQueryParam If value is FAVORITES_ONLY, then only objects marked as favorite by the requesting user will be included in result. If value is NON_FAVORITES_ONLY, then objects marked as favorites by the requesting user will be skipped. If value is ALL or if not specified, all objects, irrespective of favorites or not will be returned. Default is ALL.
         * 
         * @return builder
         * 
         */
        public Builder favoritesQueryParam(@Nullable Output<String> favoritesQueryParam) {
            $.favoritesQueryParam = favoritesQueryParam;
            return this;
        }

        /**
         * @param favoritesQueryParam If value is FAVORITES_ONLY, then only objects marked as favorite by the requesting user will be included in result. If value is NON_FAVORITES_ONLY, then objects marked as favorites by the requesting user will be skipped. If value is ALL or if not specified, all objects, irrespective of favorites or not will be returned. Default is ALL.
         * 
         * @return builder
         * 
         */
        public Builder favoritesQueryParam(String favoritesQueryParam) {
            return favoritesQueryParam(Output.of(favoritesQueryParam));
        }

        /**
         * @param fields Specifies the fields to get for an object.
         * 
         * @return builder
         * 
         */
        public Builder fields(@Nullable Output<List<String>> fields) {
            $.fields = fields;
            return this;
        }

        /**
         * @param fields Specifies the fields to get for an object.
         * 
         * @return builder
         * 
         */
        public Builder fields(List<String> fields) {
            return fields(Output.of(fields));
        }

        /**
         * @param fields Specifies the fields to get for an object.
         * 
         * @return builder
         * 
         */
        public Builder fields(String... fields) {
            return fields(List.of(fields));
        }

        public Builder filters(@Nullable Output<List<GetRegistryDataAssetsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetRegistryDataAssetsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetRegistryDataAssetsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param folderId Unique key of the folder.
         * 
         * @return builder
         * 
         */
        public Builder folderId(@Nullable Output<String> folderId) {
            $.folderId = folderId;
            return this;
        }

        /**
         * @param folderId Unique key of the folder.
         * 
         * @return builder
         * 
         */
        public Builder folderId(String folderId) {
            return folderId(Output.of(folderId));
        }

        /**
         * @param includeTypes DataAsset type which needs to be listed while listing dataAssets
         * 
         * @return builder
         * 
         */
        public Builder includeTypes(@Nullable Output<List<String>> includeTypes) {
            $.includeTypes = includeTypes;
            return this;
        }

        /**
         * @param includeTypes DataAsset type which needs to be listed while listing dataAssets
         * 
         * @return builder
         * 
         */
        public Builder includeTypes(List<String> includeTypes) {
            return includeTypes(Output.of(includeTypes));
        }

        /**
         * @param includeTypes DataAsset type which needs to be listed while listing dataAssets
         * 
         * @return builder
         * 
         */
        public Builder includeTypes(String... includeTypes) {
            return includeTypes(List.of(includeTypes));
        }

        /**
         * @param name Used to filter by the name of the object.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Used to filter by the name of the object.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param registryId The registry Ocid.
         * 
         * @return builder
         * 
         */
        public Builder registryId(Output<String> registryId) {
            $.registryId = registryId;
            return this;
        }

        /**
         * @param registryId The registry Ocid.
         * 
         * @return builder
         * 
         */
        public Builder registryId(String registryId) {
            return registryId(Output.of(registryId));
        }

        /**
         * @param type Specific DataAsset Type
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type Specific DataAsset Type
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public GetRegistryDataAssetsArgs build() {
            $.registryId = Objects.requireNonNull($.registryId, "expected parameter 'registryId' to be non-null");
            return $;
        }
    }

}
