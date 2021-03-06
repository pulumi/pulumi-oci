// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataConnectivity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetRegistryFoldersFolderSummaryCollectionItemDataAssetMetadataAggregator {
    /**
     * @return User-defined description for the folder.
     * 
     */
    private final String description;
    /**
     * @return Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    private final String identifier;
    /**
     * @return Generated key that can be used in API calls to identify folder. On scenarios where reference to the folder is needed, a value can be passed in create.
     * 
     */
    private final String key;
    /**
     * @return Used to filter by the name of the object.
     * 
     */
    private final String name;
    /**
     * @return Type of the object to filter the results with.
     * 
     */
    private final String type;

    @CustomType.Constructor
    private GetRegistryFoldersFolderSummaryCollectionItemDataAssetMetadataAggregator(
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("identifier") String identifier,
        @CustomType.Parameter("key") String key,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("type") String type) {
        this.description = description;
        this.identifier = identifier;
        this.key = key;
        this.name = name;
        this.type = type;
    }

    /**
     * @return User-defined description for the folder.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    public String identifier() {
        return this.identifier;
    }
    /**
     * @return Generated key that can be used in API calls to identify folder. On scenarios where reference to the folder is needed, a value can be passed in create.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return Used to filter by the name of the object.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Type of the object to filter the results with.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRegistryFoldersFolderSummaryCollectionItemDataAssetMetadataAggregator defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String description;
        private String identifier;
        private String key;
        private String name;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRegistryFoldersFolderSummaryCollectionItemDataAssetMetadataAggregator defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.identifier = defaults.identifier;
    	      this.key = defaults.key;
    	      this.name = defaults.name;
    	      this.type = defaults.type;
        }

        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder identifier(String identifier) {
            this.identifier = Objects.requireNonNull(identifier);
            return this;
        }
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GetRegistryFoldersFolderSummaryCollectionItemDataAssetMetadataAggregator build() {
            return new GetRegistryFoldersFolderSummaryCollectionItemDataAssetMetadataAggregator(description, identifier, key, name, type);
        }
    }
}
