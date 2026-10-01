package scanner

import (
	"github.com/CompassSecurity/pipeleek/pkg/scanner/artifact"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/engine"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/rules"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/types"
)

type Finding = types.Finding
type PatternElement = types.PatternElement
type PatternPattern = types.PatternPattern
type SecretsPatterns = types.SecretsPatterns
type DetectionResult = types.DetectionResult
type DetectionOptions = engine.DetectionOptions

var InitRules = rules.InitRules
var DownloadRules = rules.DownloadRules
var AppendPipeleekRules = rules.AppendPipeleekRules

var DetectHits = engine.DetectHits
var DetectHitsWithOptions = engine.DetectHitsWithOptions

var DetectFileHits = artifact.DetectFileHits
var HandleArchiveArtifact = artifact.HandleArchiveArtifact
