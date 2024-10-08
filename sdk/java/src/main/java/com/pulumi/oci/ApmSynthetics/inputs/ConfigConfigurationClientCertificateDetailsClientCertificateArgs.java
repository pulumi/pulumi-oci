// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConfigConfigurationClientCertificateDetailsClientCertificateArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConfigConfigurationClientCertificateDetailsClientCertificateArgs Empty = new ConfigConfigurationClientCertificateDetailsClientCertificateArgs();

    /**
     * (Updatable) Content of the client certificate file.
     * 
     */
    @Import(name="content")
    private @Nullable Output<String> content;

    /**
     * @return (Updatable) Content of the client certificate file.
     * 
     */
    public Optional<Output<String>> content() {
        return Optional.ofNullable(this.content);
    }

    /**
     * (Updatable) Name of the certificate file. The name should not contain any confidential information.
     * 
     */
    @Import(name="fileName")
    private @Nullable Output<String> fileName;

    /**
     * @return (Updatable) Name of the certificate file. The name should not contain any confidential information.
     * 
     */
    public Optional<Output<String>> fileName() {
        return Optional.ofNullable(this.fileName);
    }

    private ConfigConfigurationClientCertificateDetailsClientCertificateArgs() {}

    private ConfigConfigurationClientCertificateDetailsClientCertificateArgs(ConfigConfigurationClientCertificateDetailsClientCertificateArgs $) {
        this.content = $.content;
        this.fileName = $.fileName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConfigConfigurationClientCertificateDetailsClientCertificateArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConfigConfigurationClientCertificateDetailsClientCertificateArgs $;

        public Builder() {
            $ = new ConfigConfigurationClientCertificateDetailsClientCertificateArgs();
        }

        public Builder(ConfigConfigurationClientCertificateDetailsClientCertificateArgs defaults) {
            $ = new ConfigConfigurationClientCertificateDetailsClientCertificateArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param content (Updatable) Content of the client certificate file.
         * 
         * @return builder
         * 
         */
        public Builder content(@Nullable Output<String> content) {
            $.content = content;
            return this;
        }

        /**
         * @param content (Updatable) Content of the client certificate file.
         * 
         * @return builder
         * 
         */
        public Builder content(String content) {
            return content(Output.of(content));
        }

        /**
         * @param fileName (Updatable) Name of the certificate file. The name should not contain any confidential information.
         * 
         * @return builder
         * 
         */
        public Builder fileName(@Nullable Output<String> fileName) {
            $.fileName = fileName;
            return this;
        }

        /**
         * @param fileName (Updatable) Name of the certificate file. The name should not contain any confidential information.
         * 
         * @return builder
         * 
         */
        public Builder fileName(String fileName) {
            return fileName(Output.of(fileName));
        }

        public ConfigConfigurationClientCertificateDetailsClientCertificateArgs build() {
            return $;
        }
    }

}
