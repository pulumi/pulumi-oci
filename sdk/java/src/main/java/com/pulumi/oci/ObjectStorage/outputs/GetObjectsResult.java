// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ObjectStorage.outputs.GetObjectsFilter;
import com.pulumi.oci.ObjectStorage.outputs.GetObjectsObject;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetObjectsResult {
    private String bucket;
    private @Nullable String delimiter;
    private @Nullable String end;
    private @Nullable List<GetObjectsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String namespace;
    /**
     * @return The list of list_objects.
     * 
     */
    private List<GetObjectsObject> objects;
    private @Nullable String prefix;
    private List<String> prefixes;
    private @Nullable String start;
    private @Nullable String startAfter;

    private GetObjectsResult() {}
    public String bucket() {
        return this.bucket;
    }
    public Optional<String> delimiter() {
        return Optional.ofNullable(this.delimiter);
    }
    public Optional<String> end() {
        return Optional.ofNullable(this.end);
    }
    public List<GetObjectsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return The list of list_objects.
     * 
     */
    public List<GetObjectsObject> objects() {
        return this.objects;
    }
    public Optional<String> prefix() {
        return Optional.ofNullable(this.prefix);
    }
    public List<String> prefixes() {
        return this.prefixes;
    }
    public Optional<String> start() {
        return Optional.ofNullable(this.start);
    }
    public Optional<String> startAfter() {
        return Optional.ofNullable(this.startAfter);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetObjectsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bucket;
        private @Nullable String delimiter;
        private @Nullable String end;
        private @Nullable List<GetObjectsFilter> filters;
        private String id;
        private String namespace;
        private List<GetObjectsObject> objects;
        private @Nullable String prefix;
        private List<String> prefixes;
        private @Nullable String start;
        private @Nullable String startAfter;
        public Builder() {}
        public Builder(GetObjectsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.delimiter = defaults.delimiter;
    	      this.end = defaults.end;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.namespace = defaults.namespace;
    	      this.objects = defaults.objects;
    	      this.prefix = defaults.prefix;
    	      this.prefixes = defaults.prefixes;
    	      this.start = defaults.start;
    	      this.startAfter = defaults.startAfter;
        }

        @CustomType.Setter
        public Builder bucket(String bucket) {
            this.bucket = Objects.requireNonNull(bucket);
            return this;
        }
        @CustomType.Setter
        public Builder delimiter(@Nullable String delimiter) {
            this.delimiter = delimiter;
            return this;
        }
        @CustomType.Setter
        public Builder end(@Nullable String end) {
            this.end = end;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetObjectsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetObjectsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }
        @CustomType.Setter
        public Builder objects(List<GetObjectsObject> objects) {
            this.objects = Objects.requireNonNull(objects);
            return this;
        }
        public Builder objects(GetObjectsObject... objects) {
            return objects(List.of(objects));
        }
        @CustomType.Setter
        public Builder prefix(@Nullable String prefix) {
            this.prefix = prefix;
            return this;
        }
        @CustomType.Setter
        public Builder prefixes(List<String> prefixes) {
            this.prefixes = Objects.requireNonNull(prefixes);
            return this;
        }
        public Builder prefixes(String... prefixes) {
            return prefixes(List.of(prefixes));
        }
        @CustomType.Setter
        public Builder start(@Nullable String start) {
            this.start = start;
            return this;
        }
        @CustomType.Setter
        public Builder startAfter(@Nullable String startAfter) {
            this.startAfter = startAfter;
            return this;
        }
        public GetObjectsResult build() {
            final var o = new GetObjectsResult();
            o.bucket = bucket;
            o.delimiter = delimiter;
            o.end = end;
            o.filters = filters;
            o.id = id;
            o.namespace = namespace;
            o.objects = objects;
            o.prefix = prefix;
            o.prefixes = prefixes;
            o.start = start;
            o.startAfter = startAfter;
            return o;
        }
    }
}