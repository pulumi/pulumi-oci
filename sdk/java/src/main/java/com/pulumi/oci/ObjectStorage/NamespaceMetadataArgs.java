// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NamespaceMetadataArgs extends com.pulumi.resources.ResourceArgs {

    public static final NamespaceMetadataArgs Empty = new NamespaceMetadataArgs();

    @Import(name="defaultS3compartmentId")
    private @Nullable Output<String> defaultS3compartmentId;

    public Optional<Output<String>> defaultS3compartmentId() {
        return Optional.ofNullable(this.defaultS3compartmentId);
    }

    @Import(name="defaultSwiftCompartmentId")
    private @Nullable Output<String> defaultSwiftCompartmentId;

    public Optional<Output<String>> defaultSwiftCompartmentId() {
        return Optional.ofNullable(this.defaultSwiftCompartmentId);
    }

    @Import(name="namespace", required=true)
    private Output<String> namespace;

    public Output<String> namespace() {
        return this.namespace;
    }

    private NamespaceMetadataArgs() {}

    private NamespaceMetadataArgs(NamespaceMetadataArgs $) {
        this.defaultS3compartmentId = $.defaultS3compartmentId;
        this.defaultSwiftCompartmentId = $.defaultSwiftCompartmentId;
        this.namespace = $.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NamespaceMetadataArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NamespaceMetadataArgs $;

        public Builder() {
            $ = new NamespaceMetadataArgs();
        }

        public Builder(NamespaceMetadataArgs defaults) {
            $ = new NamespaceMetadataArgs(Objects.requireNonNull(defaults));
        }

        public Builder defaultS3compartmentId(@Nullable Output<String> defaultS3compartmentId) {
            $.defaultS3compartmentId = defaultS3compartmentId;
            return this;
        }

        public Builder defaultS3compartmentId(String defaultS3compartmentId) {
            return defaultS3compartmentId(Output.of(defaultS3compartmentId));
        }

        public Builder defaultSwiftCompartmentId(@Nullable Output<String> defaultSwiftCompartmentId) {
            $.defaultSwiftCompartmentId = defaultSwiftCompartmentId;
            return this;
        }

        public Builder defaultSwiftCompartmentId(String defaultSwiftCompartmentId) {
            return defaultSwiftCompartmentId(Output.of(defaultSwiftCompartmentId));
        }

        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        public NamespaceMetadataArgs build() {
            $.namespace = Objects.requireNonNull($.namespace, "expected parameter 'namespace' to be non-null");
            return $;
        }
    }

}