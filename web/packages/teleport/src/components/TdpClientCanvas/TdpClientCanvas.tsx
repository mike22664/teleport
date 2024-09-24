/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import React, { memo, useEffect } from 'react';
import { DebouncedFunc } from 'shared/utils/highbar';

import type { CSSProperties, MutableRefObject } from 'react';

function TdpClientCanvas(props: Props) {
  const {
    canvasRef,
    onKeyDown,
    onKeyUp,
    onFocusOut,
    onMouseMove,
    onMouseDownDS,
    onMouseUp,
    onMouseWheelScroll,
    windowOnResize,
    style,
  } = props;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (canvas) {
      // Make the canvas a focusable keyboard listener
      // https://stackoverflow.com/a/51267699/6277051
      // https://stackoverflow.com/a/16492878/6277051
      canvas.tabIndex = -1;
      canvas.style.outline = 'none';
      canvas.focus();
    }
  }, [canvasRef]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) {
      return;
    }

    console.log('im ruinign on');
    window.addEventListener('resize', windowOnResize);
    canvas.addEventListener('mousemove', onMouseMove);
    canvas.oncontextmenu = _contextMenu;
    canvas.addEventListener('mousedown', onMouseDownDS);
    canvas.addEventListener('mouseup', onMouseUp);
    canvas.addEventListener('wheel', onMouseWheelScroll);
    canvas.addEventListener('keydown', onKeyDown);
    canvas.addEventListener('keyup', onKeyUp);
    canvas.addEventListener('focusout', onFocusOut);

    return () => {
      console.log('!!!!canvas cleaning up!!!!!');
      window.removeEventListener('resize', windowOnResize);
      canvas.removeEventListener('mousemove', onMouseMove);
      canvas.removeEventListener('contextmenu', _contextMenu);
      canvas.removeEventListener('mousedown', onMouseDownDS);
      canvas.removeEventListener('mouseup', onMouseUp);
      canvas.removeEventListener('wheel', onMouseWheelScroll);
      canvas.removeEventListener('keydown', onKeyDown);
      canvas.removeEventListener('keyup', onKeyUp);
      canvas.removeEventListener('focusout', onFocusOut);
    };
  }, [canvasRef]);

  // useEffect(() => {
  //   if (client) {
  //     const canvas = canvasRef.current;
  //     const _clearCanvas = () => {
  //       const ctx = canvas.getContext('2d');
  //       ctx.clearRect(0, 0, canvas.width, canvas.height);
  //     };
  //     client.on(TdpClientEvent.RESET, _clearCanvas);

  //     return () => {
  //       client.removeListener(TdpClientEvent.RESET, _clearCanvas);
  //     };
  //   }
  // }, [client]);

  return <canvas style={{ ...style }} ref={canvasRef} />;
}

export type Props = {
  canvasRef: MutableRefObject<HTMLCanvasElement>;
  onKeyDown?: (e: KeyboardEvent) => any;
  onKeyUp?: (e: KeyboardEvent) => any;
  onFocusOut?: () => any;
  onMouseMove?: (e: MouseEvent) => any;
  onMouseDownDS?: (e: MouseEvent) => any;
  onMouseUp?: (e: MouseEvent) => any;
  onMouseWheelScroll?: (e: WheelEvent) => any;
  onContextMenu?: () => boolean;
  windowOnResize?: DebouncedFunc<() => void>;
  style?: CSSProperties;
  updatePointer?: boolean;
};

export default memo(TdpClientCanvas);

function _contextMenu() {
  return false;
}
