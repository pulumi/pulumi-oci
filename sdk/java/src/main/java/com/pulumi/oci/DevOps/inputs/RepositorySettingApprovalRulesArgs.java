// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DevOps.inputs.RepositorySettingApprovalRulesItemArgs;
import java.util.List;
import java.util.Objects;


public final class RepositorySettingApprovalRulesArgs extends com.pulumi.resources.ResourceArgs {

    public static final RepositorySettingApprovalRulesArgs Empty = new RepositorySettingApprovalRulesArgs();

    /**
     * (Updatable) List of approval rules.
     * 
     */
    @Import(name="items", required=true)
    private Output<List<RepositorySettingApprovalRulesItemArgs>> items;

    /**
     * @return (Updatable) List of approval rules.
     * 
     */
    public Output<List<RepositorySettingApprovalRulesItemArgs>> items() {
        return this.items;
    }

    private RepositorySettingApprovalRulesArgs() {}

    private RepositorySettingApprovalRulesArgs(RepositorySettingApprovalRulesArgs $) {
        this.items = $.items;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RepositorySettingApprovalRulesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RepositorySettingApprovalRulesArgs $;

        public Builder() {
            $ = new RepositorySettingApprovalRulesArgs();
        }

        public Builder(RepositorySettingApprovalRulesArgs defaults) {
            $ = new RepositorySettingApprovalRulesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param items (Updatable) List of approval rules.
         * 
         * @return builder
         * 
         */
        public Builder items(Output<List<RepositorySettingApprovalRulesItemArgs>> items) {
            $.items = items;
            return this;
        }

        /**
         * @param items (Updatable) List of approval rules.
         * 
         * @return builder
         * 
         */
        public Builder items(List<RepositorySettingApprovalRulesItemArgs> items) {
            return items(Output.of(items));
        }

        /**
         * @param items (Updatable) List of approval rules.
         * 
         * @return builder
         * 
         */
        public Builder items(RepositorySettingApprovalRulesItemArgs... items) {
            return items(List.of(items));
        }

        public RepositorySettingApprovalRulesArgs build() {
            if ($.items == null) {
                throw new MissingRequiredPropertyException("RepositorySettingApprovalRulesArgs", "items");
            }
            return $;
        }
    }

}
