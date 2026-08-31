package service

// UserDeviceBlocksModel applies the administrator's exact client model ID rule.
func UserDeviceBlocksModel(controls UserDeviceRequestControls, modelName string) bool {
	for _, blockedModel := range controls.BlockedModels {
		if blockedModel == modelName {
			return true
		}
	}
	return false
}
