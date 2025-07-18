// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BdsInstanceNodeBackupConfigurationLevelTypeDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final BdsInstanceNodeBackupConfigurationLevelTypeDetailsArgs Empty = new BdsInstanceNodeBackupConfigurationLevelTypeDetailsArgs();

    /**
     * (Updatable) Type of level used to trigger the creation of a new node backup configuration or node replacement configuration.
     * 
     */
    @Import(name="levelType", required=true)
    private Output<String> levelType;

    /**
     * @return (Updatable) Type of level used to trigger the creation of a new node backup configuration or node replacement configuration.
     * 
     */
    public Output<String> levelType() {
        return this.levelType;
    }

    /**
     * (Updatable) Host name of the node to create backup configuration.
     * 
     */
    @Import(name="nodeHostName")
    private @Nullable Output<String> nodeHostName;

    /**
     * @return (Updatable) Host name of the node to create backup configuration.
     * 
     */
    public Optional<Output<String>> nodeHostName() {
        return Optional.ofNullable(this.nodeHostName);
    }

    /**
     * (Updatable) Type of the node or nodes of the node backup configuration or node replacement configuration which are going to be created. Accepted values are MASTER and UTILITY.
     * 
     */
    @Import(name="nodeType")
    private @Nullable Output<String> nodeType;

    /**
     * @return (Updatable) Type of the node or nodes of the node backup configuration or node replacement configuration which are going to be created. Accepted values are MASTER and UTILITY.
     * 
     */
    public Optional<Output<String>> nodeType() {
        return Optional.ofNullable(this.nodeType);
    }

    private BdsInstanceNodeBackupConfigurationLevelTypeDetailsArgs() {}

    private BdsInstanceNodeBackupConfigurationLevelTypeDetailsArgs(BdsInstanceNodeBackupConfigurationLevelTypeDetailsArgs $) {
        this.levelType = $.levelType;
        this.nodeHostName = $.nodeHostName;
        this.nodeType = $.nodeType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BdsInstanceNodeBackupConfigurationLevelTypeDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BdsInstanceNodeBackupConfigurationLevelTypeDetailsArgs $;

        public Builder() {
            $ = new BdsInstanceNodeBackupConfigurationLevelTypeDetailsArgs();
        }

        public Builder(BdsInstanceNodeBackupConfigurationLevelTypeDetailsArgs defaults) {
            $ = new BdsInstanceNodeBackupConfigurationLevelTypeDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param levelType (Updatable) Type of level used to trigger the creation of a new node backup configuration or node replacement configuration.
         * 
         * @return builder
         * 
         */
        public Builder levelType(Output<String> levelType) {
            $.levelType = levelType;
            return this;
        }

        /**
         * @param levelType (Updatable) Type of level used to trigger the creation of a new node backup configuration or node replacement configuration.
         * 
         * @return builder
         * 
         */
        public Builder levelType(String levelType) {
            return levelType(Output.of(levelType));
        }

        /**
         * @param nodeHostName (Updatable) Host name of the node to create backup configuration.
         * 
         * @return builder
         * 
         */
        public Builder nodeHostName(@Nullable Output<String> nodeHostName) {
            $.nodeHostName = nodeHostName;
            return this;
        }

        /**
         * @param nodeHostName (Updatable) Host name of the node to create backup configuration.
         * 
         * @return builder
         * 
         */
        public Builder nodeHostName(String nodeHostName) {
            return nodeHostName(Output.of(nodeHostName));
        }

        /**
         * @param nodeType (Updatable) Type of the node or nodes of the node backup configuration or node replacement configuration which are going to be created. Accepted values are MASTER and UTILITY.
         * 
         * @return builder
         * 
         */
        public Builder nodeType(@Nullable Output<String> nodeType) {
            $.nodeType = nodeType;
            return this;
        }

        /**
         * @param nodeType (Updatable) Type of the node or nodes of the node backup configuration or node replacement configuration which are going to be created. Accepted values are MASTER and UTILITY.
         * 
         * @return builder
         * 
         */
        public Builder nodeType(String nodeType) {
            return nodeType(Output.of(nodeType));
        }

        public BdsInstanceNodeBackupConfigurationLevelTypeDetailsArgs build() {
            if ($.levelType == null) {
                throw new MissingRequiredPropertyException("BdsInstanceNodeBackupConfigurationLevelTypeDetailsArgs", "levelType");
            }
            return $;
        }
    }

}
